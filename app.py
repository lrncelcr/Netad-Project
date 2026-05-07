"""
app.py
──────
Netad Web Dashboard — Flask Backend
Serves the HTML dashboard and exposes API endpoints for
logs, stats, login, and the MJPEG camera stream.

Run:  python app.py
Then visit:  http://192.168.1.20:5000
"""
import cv2
import os
import psycopg2
from flask import Flask, render_template, Response, jsonify, request, session
from datetime import datetime
from functools import wraps
from dotenv import load_dotenv

# Import auth helpers (same auth.py as main.py)
from auth import verify_login, log_login_event, db_connect

load_dotenv()

app        = Flask(__name__)
app.secret_key = os.urandom(32)   # Change to a fixed key in production

ALERTS_DIR  = "security_alerts"
CAMERA_SRC  = 0   # 0 = webcam | "rtsp://192.168.1.10:554/stream1" for IP cam

os.makedirs(ALERTS_DIR, exist_ok=True)

# ─── CAMERA ───────────────────────────────────────────
# --- CAMERA ---
cap = cv2.VideoCapture(CAMERA_SRC)

# Add this check right after
if not cap.isOpened():
    print("⚠️ Warning: Camera source not found. (Normal on Railway)")

def gen_frames():
    """MJPEG generator for the /video_feed endpoint."""
    while True:
        success, frame = cap.read()
        if not success:
            break
        _, buf = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 75])
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + buf.tobytes() + b'\r\n')


# ─── AUTH DECORATOR ───────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('username'):
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated


# ─── ROUTES ───────────────────────────────────────────

@app.route('/')
def index():
    # If the user is NOT logged in, show the login page
    if not session.get('username'):
        return render_template('login.html')
    
    # ONLY if they are logged in, show the dashboard
    return render_template('dashboard.html')


@app.route('/video_feed')
@login_required
def video_feed():
    return Response(
        gen_frames(),
        mimetype='multipart/x-mixed-replace; boundary=frame'
    )


# ── API: Login ──────────────────────────────────────

@app.route('/api/login', methods=['POST'])
def api_login():
    body     = request.get_json(force=True)
    username = (body.get('username') or '').strip()
    password = (body.get('password') or '').strip()

    success, result = verify_login(username, password)

    if success:
        log_login_event(username, 'Success')
        session['username'] = username
        session['role']     = result
        return jsonify({'success': True, 'username': username, 'role': result})
    else:
        log_login_event(username, 'Failed', result)
        return jsonify({'success': False, 'message': result})


@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'success': True})


# ── API: Security Events ────────────────────────────

@app.route('/api/logs')
@login_required
def api_logs():
    try:
        conn = db_connect()
        cur  = conn.cursor()
        cur.execute(
            "SELECT timestamp, ip_address, action, status FROM audit_logs ORDER BY timestamp DESC LIMIT 30"
        )
        rows = cur.fetchall()
        cur.close(); conn.close()
        return jsonify([
            {
                'ts':  r[0].strftime('%Y-%m-%d  %H:%M:%S'),
                'ip':  r[1],
                'act': r[2],
                'stat': r[3]
            } for r in rows
        ])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── API: Login History ──────────────────────────────

@app.route('/api/login_logs')
@login_required
def api_login_logs():
    try:
        conn = db_connect()
        cur  = conn.cursor()
        cur.execute(
            "SELECT timestamp, username, ip_address, status, reason FROM login_logs ORDER BY timestamp DESC LIMIT 30"
        )
        rows = cur.fetchall()
        cur.close(); conn.close()
        return jsonify([
            {
                'ts':       r[0].strftime('%Y-%m-%d  %H:%M:%S'),
                'username': r[1],
                'ip':       r[2],
                'status':   r[3],
                'reason':   r[4] or ''
            } for r in rows
        ])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── API: Stats ──────────────────────────────────────

# ... (API: Login and API: Security Events are above this) ...

# ── API: Stats ──────────────────────────────────────
@app.route('/api/stats')
@login_required
def api_stats():
    try:
        conn = db_connect()
        cur  = conn.cursor()

        # Fetches Critical Events Count
        cur.execute("SELECT COUNT(*) FROM audit_logs WHERE status = 'Critical'")
        critical = cur.fetchone()[0]

        # Fetches Total Alerts Count
        cur.execute("SELECT COUNT(*) FROM audit_logs")
        total = cur.fetchone()[0]

        # Fetches Total Login Attempts
        cur.execute("SELECT COUNT(*) FROM login_logs")
        logins = cur.fetchone()[0]

        # Fetches Failed Logins
        cur.execute("SELECT COUNT(*) FROM login_logs WHERE status = 'Failed'")
        failed = cur.fetchone()[0]

        cur.close(); conn.close()

        # Counts local JPEG snapshots in your folder
        snaps = len([f for f in os.listdir(ALERTS_DIR) if f.endswith('.jpg')])

        # Sends everything to the website as JSON
        return jsonify({
            'critical': critical,
            'total':    total,
            'logins':   logins,
            'failed':   failed,
            'snaps':    snaps
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── ENTRY POINT ──────────────────────────────────────
if __name__ == '__main__':
    # Railway provides the port via an environment variable
    port = int(os.environ.get("PORT", 5000)) 
    app.run(host='0.0.0.0', port=port, debug=False)