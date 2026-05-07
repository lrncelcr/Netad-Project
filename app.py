import cv2
import os
import psycopg2
from flask import Flask, render_template, Response, jsonify, request, session
from datetime import datetime
from functools import wraps
from dotenv import load_dotenv

# Import auth helpers
from auth import verify_login, log_login_event, db_connect

load_dotenv()

app = Flask(__name__)
# Uses Railway Variable if available, otherwise uses a fallback
app.secret_key = os.getenv("SECRET_KEY", "netad-super-secret-key-2026") 

ALERTS_DIR = "security_alerts"
CAMERA_SRC = 0 
os.makedirs(ALERTS_DIR, exist_ok=True)

# ─── CAMERA FAIL-SAFE ─────────────────────────────────
cap = cv2.VideoCapture(CAMERA_SRC)
if not cap.isOpened():
    print("⚠️ Warning: Camera source not found. (Normal on Railway)")

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

# ─── AUTH DECORATOR ───────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('username'):
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

# ─── MAIN ROUTES ──────────────────────────────────────
@app.route('/')
def index():
    if not session.get('username'):
        return render_template('login.html')
    return render_template('dashboard.html')

@app.route('/video_feed')
@login_required
def video_feed():
    return Response(gen_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')

# ─── API: AUTHENTICATION ──────────────────────────────
@app.route('/api/login', methods=['POST'])
def api_login():
    body = request.get_json(force=True)
    username = (body.get('username') or '').strip()
    password = (body.get('password') or '').strip()

    # Cloud-friendly IP detection
    if request.headers.get('X-Forwarded-For'):
        ip_addr = request.headers.get('X-Forwarded-For').split(',')[0]
    else:
        ip_addr = request.remote_addr

    success, result = verify_login(username, password)

    if success:
        log_login_event(username, 'Success', ip_address=ip_addr)
        session['username'] = username
        session['role'] = result
        return jsonify({'success': True, 'username': username, 'role': result})
    else:
        log_login_event(username, 'Failed', result, ip_address=ip_addr)
        return jsonify({'success': False, 'message': result})

@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'success': True})

# ─── API: DATA & LOGS ─────────────────────────────────
@app.route('/api/logs')
@login_required
def api_logs():
    try:
        conn = db_connect()
        cur = conn.cursor()
        cur.execute("SELECT timestamp, ip_address, action, status FROM audit_logs ORDER BY timestamp DESC LIMIT 30")
        rows = cur.fetchall()
        cur.close(); conn.close()
        return jsonify([{'ts': r[0].strftime('%Y-%m-%d %H:%M:%S'), 'ip': r[1], 'act': r[2], 'stat': r[3]} for r in rows])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/login_logs')
@login_required
def api_login_logs():
    try:
        conn = db_connect()
        cur = conn.cursor()
        cur.execute("SELECT timestamp, username, ip_address, status, reason FROM login_logs ORDER BY timestamp DESC LIMIT 30")
        rows = cur.fetchall()
        cur.close(); conn.close()
        return jsonify([{'ts': r[0].strftime('%H:%M:%S'), 'username': r[1], 'ip': r[2], 'status': r[3], 'reason': r[4] or ''} for r in rows])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats')
@login_required
def api_stats():
    try:
        conn = db_connect()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM audit_logs WHERE status = 'Critical'"); critical = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM audit_logs"); total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM login_logs"); logins = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM login_logs WHERE status = 'Failed'"); failed = cur.fetchone()[0]
        cur.close(); conn.close()
        snaps = len([f for f in os.listdir(ALERTS_DIR) if f.endswith('.jpg')])
        return jsonify({'critical': critical, 'total': total, 'logins': logins, 'failed': failed, 'snaps': snaps})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── RUN SERVER ───────────────────────────────────────
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)