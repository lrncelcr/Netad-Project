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

# Import hardened security layer
from security import (
    block_if_locked,
    record_failed_login,
    clear_failed_logins,
    register_threat,
    sanitise_username,
    sanitise_text,
    get_real_ip,
    add_security_headers,
    get_recent_threats,
)

load_dotenv()

app = Flask(__name__)

# ─── SESSION / COOKIE HARDENING ───────────────────────────
app.secret_key = os.getenv("SECRET_KEY")
if not app.secret_key or len(app.secret_key) < 32:
    raise RuntimeError(
        "SECRET_KEY env var is missing or too short (must be ≥32 chars). "
    )

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("FLASK_ENV") != "development",
    PERMANENT_SESSION_LIFETIME=3600,
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,
)

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

# ─── AUTH DECORATORS ──────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('username'):
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('username'):
            return jsonify({'error': 'Unauthorized'}), 401
        
        # Case-insensitive role comparison with an 'admin' username fail-safe
        user_role = str(session.get('role') or '').lower().strip()
        user_name = str(session.get('username') or '').lower().strip()
        
        if user_role != 'admin' and user_name != 'admin':
            return jsonify({'error': 'Forbidden: admin access required'}), 403
            
        return f(*args, **kwargs)
    return decorated


# ─── MAIN ROUTES ──────────────────────────────────────────
@app.route('/')
def index():
    if not session.get('username'):
        return render_template('login.html')
    return render_template('dashboard.html')

@app.route('/api/me')
@login_required
def api_me():
    return jsonify({
        'username': session.get('username'),
        'role': session.get('role')
    })

@app.route('/video_feed')
@login_required
def video_feed():
    return Response(gen_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')


# ─── API: AUTHENTICATION ──────────────────────────────────
@app.route('/api/login', methods=['POST'])
@block_if_locked
def api_login():
    ip_addr = get_real_ip()

    if request.content_length and request.content_length > 4096:
        return jsonify({'success': False, 'message': 'Request too large'}), 413

    body = request.get_json(force=True, silent=True) or {}

    username = sanitise_username(body.get('username') or '')
    if username is None:
        return jsonify({'success': False, 'message': 'Invalid username format.'}), 400
    password = (body.get('password') or '').strip()[:128]

    success, result = verify_login(username, password)

    if success:
        clear_failed_logins(ip_addr)
        log_login_event(username, 'Success', ip_address=ip_addr)
        session.clear()
        session['username'] = username
        session['role'] = result
        session.permanent = True
        return jsonify({'success': True, 'username': username, 'role': result})

    else:
        log_login_event(username, 'Failed', result, ip_address=ip_addr)
        rate_result = record_failed_login(ip_addr)

        if rate_result['blocked']:
            try:
                conn = db_connect()
                cur = conn.cursor()
                cur.execute(
                    "INSERT INTO audit_logs (ip_address, action, status) VALUES (%s, %s, %s)",
                    (ip_addr, f"Brute Force: IP blocked after {rate_result['attempts']} failed logins for '{username}'", "Critical")
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
                    (ip_addr, f"Brute Force: 5+ failed logins for '{username}' in last 10 min", "Critical")
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
    username = session.get('username')
    if username:
        ip_addr = get_real_ip()
        # Log the logout action into the database before clearing the session!
        log_login_event(username, 'Logout', ip_addr)
    
    session.clear()
    return jsonify({'success': True})


# ─── API: USER MANAGEMENT (Locked down to Admins) ─────────
@app.route('/api/add_user', methods=['POST'])
@admin_required
def api_add_user():
    body = request.get_json(force=True, silent=True) or {}
    new_username = sanitise_username(body.get('username') or '')
    if new_username is None:
        return jsonify({'success': False, 'message': 'Invalid username (a-z, 0-9, _ - . only)'}), 400

    new_password = (body.get('password') or '').strip()
    if len(new_password) < 8:
        return jsonify({'success': False, 'message': 'Password must be at least 8 characters'}), 400

    success, message = create_user(new_username, new_password)
    
    # FIXED: Added logic correctly inside the function
    if success:
        ip_addr = get_real_ip()
        conn = db_connect()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO audit_logs (ip_address, action, status) VALUES (%s, %s, %s)",
            (ip_addr, f"Admin '{session.get('username')}' provisioned new user '{new_username}'", "Info")
        )
        conn.commit()
        cur.close(); conn.close()
        
    return jsonify({'success': success, 'message': message})


@app.route('/api/get_users')
@admin_required
def api_get_users():
    try:
        current_user = session.get('username')
        conn = db_connect()
        cur = conn.cursor()
        
        cur.execute("""
            SELECT u.username, u.role, 
                   (SELECT MAX(timestamp) FROM login_logs WHERE username = u.username AND status = 'Success') as last_login,
                   (SELECT MAX(timestamp) >= NOW() - INTERVAL '1 hour' FROM login_logs WHERE username = u.username AND status = 'Success') as is_recent
            FROM users u ORDER BY u.username ASC
        """)
        rows = cur.fetchall()
        cur.close(); conn.close()

        user_list = []
        for r in rows:
            uname = r[0]
            role = r[1]
            last_login = r[2]
            is_recent = r[3]

            if last_login:
                last_active_str = last_login.strftime('%Y-%m-%d, %H:%M:%S')
            else:
                last_active_str = "Never"

            if uname == current_user or is_recent:
                status = "Online"
            else:
                status = "Offline"

            user_list.append({
                'username': uname, 'role': role, 'last_active': last_active_str, 'status': status
            })
            
        return jsonify(user_list)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/revoke_user', methods=['POST'])
@admin_required
def api_revoke_user():
    body = request.get_json(force=True, silent=True) or {}
    target_user = sanitise_username(body.get('username') or '')

    if not target_user:
        return jsonify({'success': False, 'message': 'Invalid username'}), 400
    if target_user == session.get('username'):
        return jsonify({'success': False, 'message': 'Safety: Cannot revoke your own access'}), 400
    try:
        conn = db_connect()
        cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE username = %s", (target_user,))
        cur.execute(
            "INSERT INTO audit_logs (ip_address, action, status) VALUES (%s, %s, %s)",
            (get_real_ip(), f"Admin '{session.get('username')}' revoked access for '{target_user}'", "Warning")
        )
        conn.commit()
        cur.close(); conn.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# ─── API: THREAT TRACKING (Locked down to Admins) ──────────
@app.route('/api/threats')
@admin_required
def api_threats():
    try:
        return jsonify(get_recent_threats(20))
    except Exception as e:
        print("Threat API Error:", e)
        return jsonify([])

@app.route('/api/blocked_ips')
@admin_required
def api_blocked_ips():
    try:
        conn = db_connect()
        cur = conn.cursor()
        cur.execute("""
            SELECT ip_address, 
                   EXTRACT(EPOCH FROM (NOW() - MAX(timestamp))) as seconds_ago
            FROM login_logs 
            WHERE status = 'Failed' AND timestamp >= NOW() - INTERVAL '5 minutes'
            GROUP BY ip_address
            HAVING COUNT(*) >= 5
        """)
        rows = cur.fetchall()
        cur.close(); conn.close()
        
        blocked_dict = {}
        for r in rows:
            ip = r[0] if r[0] else "UNKNOWN_IP"
            seconds_ago = r[1]
            time_left = 300 - int(seconds_ago)
            if time_left > 0:
                blocked_dict[ip] = time_left
                
        return jsonify(blocked_dict)
    except Exception as e:
        print("Blocked IPs Error:", e)
        return jsonify({})

@app.route('/api/unblock_ip', methods=['POST'])
@admin_required
def api_unblock_ip():
    try:
        data = request.get_json()
        ip_to_unblock = data.get('ip')
        
        if ip_to_unblock:
            conn = db_connect()
            cur = conn.cursor()
            
            # FIXED: Separated the queries correctly
            cur.execute("""
                UPDATE login_logs 
                SET status = 'Unblocked' 
                WHERE ip_address = %s AND status = 'Failed'
            """, (ip_to_unblock,))
            
            cur.execute(
                "INSERT INTO audit_logs (ip_address, action, status) VALUES (%s, %s, %s)",
                (get_real_ip(), f"Admin '{session.get('username')}' manually unblocked IP '{ip_to_unblock}'", "Info")
            )
            
            conn.commit()
            cur.close(); conn.close()
            
        return jsonify({"success": True})
    except Exception as e:
        print("Unblock Error:", e)
        return jsonify({"success": False, "error": str(e)})


# ─── API: DATA & LOGS (Locked down to Admins) ──────────────
@app.route('/api/logs')
@admin_required
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
@admin_required
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
@admin_required
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
        
        cur.execute("""
            SELECT COUNT(DISTINCT ip_address) 
            FROM login_logs 
            WHERE status = 'Failed' AND timestamp >= NOW() - INTERVAL '5 minutes'
            GROUP BY ip_address HAVING COUNT(*) >= 5
        """)
        blocked_row = cur.fetchone()
        blocked_count = blocked_row[0] if blocked_row else 0
        
        cur.close(); conn.close()
        snaps = len([f for f in os.listdir(ALERTS_DIR) if f.endswith('.jpg')])
        
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)