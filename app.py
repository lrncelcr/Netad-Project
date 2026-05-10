import cv2
import os
import psycopg2
import threading
from flask import Flask, render_template, Response, jsonify, request, session
from datetime import datetime
from functools import wraps
from dotenv import load_dotenv

# Import auth helpers
from auth import verify_login, log_login_event, db_connect, create_user
from detector import start_detector

# ─── NEW: Import hardened security layer ──────────────────
from security import (
    block_if_locked,
    record_failed_login,
    clear_failed_logins,
    get_blocked_ips,
    get_recent_threats,
    register_threat,
    sanitise_username,
    sanitise_text,
    get_real_ip,
    add_security_headers,
    unblock_ip,
)

load_dotenv()

app = Flask(__name__)

# ─── SESSION / COOKIE HARDENING ───────────────────────────
app.secret_key = os.getenv("SECRET_KEY")
if not app.secret_key or len(app.secret_key) < 32:
    raise RuntimeError(
        "SECRET_KEY env var is missing or too short (must be ≥32 chars). "
        "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
    )

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,       # JS cannot read the session cookie
    SESSION_COOKIE_SAMESITE="Lax",     # Mitigates CSRF on modern browsers
    SESSION_COOKIE_SECURE=os.getenv("FLASK_ENV") != "development",  # HTTPS-only in prod
    PERMANENT_SESSION_LIFETIME=3600,   # 1-hour session max
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,  # 1 MB request body limit
)

# ─── ATTACH SECURITY HEADERS TO EVERY RESPONSE ────────────
app.after_request(add_security_headers)

ALERTS_DIR = "security_alerts"
CAMERA_SRC = 0
os.makedirs(ALERTS_DIR, exist_ok=True)

# ─── CAMERA FAIL-SAFE ─────────────────────────────────────
cap = cv2.VideoCapture(CAMERA_SRC)
if not cap.isOpened():
    print("⚠️  Warning: Camera source not found. (Normal on Railway)")


def gen_frames():
    while True:
        if cap is None or not cap.isOpened():
            break
        success, frame = cap.read()
        if not success:
            break
        _, buf = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 75])
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + buf.tobytes() + b'\r\n')


# ─── AUTH DECORATOR ───────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('username'):
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated


# ─── MAIN ROUTES ──────────────────────────────────────────
@app.route('/')
def index():
    if not session.get('username'):
        return render_template('login.html')
    return render_template('dashboard.html')


@app.route('/video_feed')
@login_required
def video_feed():
    return Response(gen_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')


# ─── API: AUTHENTICATION ──────────────────────────────────
@app.route('/api/login', methods=['POST'])
@block_if_locked          # ← server-side IP block check BEFORE any processing
def api_login():
    ip_addr = get_real_ip()

    # Reject oversized bodies early
    if request.content_length and request.content_length > 4096:
        return jsonify({'success': False, 'message': 'Request too large'}), 413

    body = request.get_json(force=True, silent=True) or {}

    # Sanitise inputs — reject if username contains illegal chars
    username = sanitise_username(body.get('username') or '')
    if username is None:
        return jsonify({'success': False,
                        'message': 'Invalid username format.'}), 400
    password = (body.get('password') or '').strip()[:128]

    success, result = verify_login(username, password)

    if success:
        clear_failed_logins(ip_addr)
        log_login_event(username, 'Success', ip_address=ip_addr)
        session.clear()                        # Prevent session fixation
        session['username'] = username
        session['role'] = result
        session.permanent = True
        return jsonify({'success': True, 'username': username, 'role': result})

    else:
        log_login_event(username, 'Failed', result, ip_address=ip_addr)

        # Server-side rate limiter
        rate_result = record_failed_login(ip_addr)

        # Also write a Critical audit log when brute-force threshold hit
        if rate_result['blocked']:
            try:
                conn = db_connect()
                cur = conn.cursor()
                cur.execute(
                    "INSERT INTO audit_logs (ip_address, action, status) VALUES (%s, %s, %s)",
                    (ip_addr,
                     f"Brute Force: IP blocked after {rate_result['attempts']} failed logins for '{username}'",
                     "Critical")
                )
                conn.commit()
                cur.close(); conn.close()
            except Exception:
                pass
            return jsonify({
                'success': False,
                'message': f"Too many failed attempts. IP blocked for 5 minutes.",
                'blocked': True
            }), 429

        # Still within rate window — also check DB-level brute force (≥5 in 10 min)
        try:
            conn = db_connect()
            cur = conn.cursor()
            cur.execute(
                "SELECT COUNT(*) FROM login_logs "
                "WHERE ip_address = %s AND status = 'Failed' "
                "AND timestamp > NOW() - INTERVAL '10 minutes'",
                (ip_addr,)
            )
            fail_count = cur.fetchone()[0]
            if fail_count >= 5:
                cur.execute(
                    "INSERT INTO audit_logs (ip_address, action, status) VALUES (%s, %s, %s)",
                    (ip_addr,
                     f"Brute Force: 5+ failed logins for '{username}' in last 10 min",
                     "Critical")
                )
                conn.commit()
                register_threat(ip_addr, f"Brute force detected ({fail_count} attempts)")
            cur.close(); conn.close()
        except Exception:
            pass

        return jsonify({
            'success': False,
            'message': result,
            'attempts_remaining': rate_result['remaining']
        })


@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'success': True})


# ─── API: USER MANAGEMENT ─────────────────────────────────
@app.route('/api/add_user', methods=['POST'])
@login_required
def api_add_user():
    body = request.get_json(force=True, silent=True) or {}

    new_username = sanitise_username(body.get('username') or '')
    if new_username is None:
        return jsonify({'success': False,
                        'message': 'Invalid username (a-z, 0-9, _ - . only)'}), 400

    new_password = (body.get('password') or '').strip()
    if len(new_password) < 8:
        return jsonify({'success': False,
                        'message': 'Password must be at least 8 characters'}), 400

    success, message = create_user(new_username, new_password)
    return jsonify({'success': success, 'message': message})


@app.route('/api/get_users')
@login_required
def api_get_users():
    try:
        conn = db_connect()
        cur = conn.cursor()
        cur.execute("SELECT username, role FROM users ORDER BY username ASC")
        rows = cur.fetchall()
        cur.close(); conn.close()
        return jsonify([{'username': r[0], 'role': r[1]} for r in rows])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/revoke_user', methods=['POST'])
@login_required
def api_revoke_user():
    body = request.get_json(force=True, silent=True) or {}
    target_user = sanitise_username(body.get('username') or '')

    if not target_user:
        return jsonify({'success': False, 'message': 'Invalid username'}), 400
    if target_user == session.get('username'):
        return jsonify({'success': False,
                        'message': 'Safety: Cannot revoke your own access'}), 400
    try:
        conn = db_connect()
        cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE username = %s", (target_user,))
        conn.commit()
        cur.close(); conn.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# ─── API: SECURITY MANAGEMENT (new endpoints) ─────────────

@app.route('/api/threats')
@login_required
def api_threats():
    """
    Returns the last 20 real-time threat events from the in-memory registry.
    Used by the dashboard to show live attack alerts without waiting for
    the 5-second polling cycle.
    """
    return jsonify(get_recent_threats(20))


@app.route('/api/blocked_ips')
@login_required
def api_blocked_ips():
    """Returns currently blocked IPs with seconds remaining."""
    return jsonify(get_blocked_ips())


@app.route('/api/unblock_ip', methods=['POST'])
@login_required
def api_unblock_ip():
    """Admin endpoint to manually release a blocked IP."""
    body = request.get_json(force=True, silent=True) or {}
    ip = sanitise_text(body.get('ip') or '', max_len=45)
    if not ip:
        return jsonify({'success': False, 'message': 'IP required'}), 400
    unblock_ip(ip)
    return jsonify({'success': True, 'message': f'{ip} unblocked'})


# ─── API: DATA & LOGS ─────────────────────────────────────
@app.route('/api/logs')
@login_required
def api_logs():
    try:
        conn = db_connect()
        cur = conn.cursor()
        cur.execute(
            "SELECT timestamp, ip_address, action, status "
            "FROM audit_logs ORDER BY timestamp DESC LIMIT 30"
        )
        rows = cur.fetchall()
        cur.close(); conn.close()
        return jsonify([
            {'ts': r[0].strftime('%Y-%m-%d %H:%M:%S'), 'ip': r[1],
             'act': r[2], 'stat': r[3]}
            for r in rows
        ])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/login_logs')
@login_required
def api_login_logs():
    try:
        conn = db_connect()
        cur = conn.cursor()
        cur.execute(
            "SELECT timestamp, username, ip_address, status, reason "
            "FROM login_logs ORDER BY timestamp DESC LIMIT 30"
        )
        rows = cur.fetchall()
        cur.close(); conn.close()
        return jsonify([
            {'ts': r[0].strftime('%H:%M:%S'), 'username': r[1],
             'ip': r[2], 'status': r[3], 'reason': r[4] or ''}
            for r in rows
        ])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/stats')
@login_required
def api_stats():
    try:
        conn = db_connect()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM audit_logs WHERE status = 'Critical'")
        critical = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM audit_logs")
        total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM login_logs")
        logins = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM login_logs WHERE status = 'Failed'")
        failed = cur.fetchone()[0]
        cur.close(); conn.close()
        snaps = len([f for f in os.listdir(ALERTS_DIR) if f.endswith('.jpg')])
        # Also surface current block count
        blocked_count = len(get_blocked_ips())
        return jsonify({
            'critical': critical, 'total': total,
            'logins': logins, 'failed': failed,
            'snaps': snaps, 'blocked': blocked_count
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── START NETWORK DETECTOR ───────────────────────────────
detector_thread = threading.Thread(target=start_detector, daemon=True)
detector_thread.start()

# ─── RUN SERVER ───────────────────────────────────────────
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)