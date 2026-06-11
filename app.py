import cv2
import os
import threading

from flask import Flask, render_template, Response, jsonify, request, session
from functools import wraps
from dotenv import load_dotenv

from auth import (
    verify_login,
    log_login_event,
    db_connect,
    create_user
)

from security import (
    block_if_locked,
    record_failed_login,
    clear_failed_logins,
    register_threat,
    sanitise_username,
    get_real_ip,
    add_security_headers,
    get_recent_threats,
)

# Only import detector locally — scapy is not available on Railway
if not os.getenv("RAILWAY_ENVIRONMENT_NAME"):
    from detector import start_detector


load_dotenv()


app = Flask(__name__)


# ─── SESSION ───────────────────────────────

app.secret_key = os.getenv("SECRET_KEY")


if not app.secret_key or len(app.secret_key) < 32:
    raise RuntimeError(
        "SECRET_KEY env var is missing or too short"
    )


app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
    PERMANENT_SESSION_LIFETIME=3600,
    MAX_CONTENT_LENGTH=1024 * 1024
)


app.after_request(add_security_headers)



# ─── CAMERA ───────────────────────────────

ALERTS_DIR = "security_alerts"

os.makedirs(
    ALERTS_DIR,
    exist_ok=True
)


env_camera = os.getenv("CCTV_URL", "").strip()


if env_camera and env_camera.strip():
    CAMERA_SRC = env_camera
    print(f"Using CCTV: {CAMERA_SRC}")
else:
    CAMERA_SRC = None
    print("Camera disabled")


if CAMERA_SRC:
    cap = cv2.VideoCapture(CAMERA_SRC)
    cap.set(cv2.CAP_PROP_OPEN_TIMEOUT_MSEC, 5000)
else:
    cap = None


if cap and not cap.isOpened():
    print("Camera source not found")
    cap = None


def gen_frames():

    while True:

        if cap is None:
            break

        success, frame = cap.read()

        if not success:
            print("Failed to read camera frame")
            break

        _, buffer = cv2.imencode(
            ".jpg",
            frame,
            [cv2.IMWRITE_JPEG_QUALITY, 75]
        )

        yield (
            b"--frame\r\n"
            b"Content-Type: image/jpeg\r\n\r\n"
            + buffer.tobytes()
            + b"\r\n"
        )


# ─── AUTH DECORATORS ──────────────────────

def login_required(f):

    @wraps(f)
    def decorated(*args, **kwargs):

        if not session.get("username"):
            return jsonify({"error": "Unauthorized"}), 401

        return f(*args, **kwargs)

    return decorated


def admin_required(f):

    @wraps(f)
    def decorated(*args, **kwargs):

        if not session.get("username"):
            return jsonify({"error": "Unauthorized"}), 401

        role     = str(session.get("role", "")).lower()
        username = str(session.get("username", "")).lower()

        if role != "admin" and username != "admin":
            return jsonify({"error": "Forbidden"}), 403

        return f(*args, **kwargs)

    return decorated


# ─── ROUTES ────────────────────────────────

@app.route("/")
def index():

    if not session.get("username"):
        return render_template("login.html")

    return render_template("dashboard.html")


@app.route("/")
def index():

    if not session.get("username"):
        return render_template("login.html")

    # Pass the cloud tunnel URL directly to the frontend template context
    return render_template("dashboard.html", cctv_src=os.getenv("CCTV_URL", ""))


@app.route("/video_feed")
@login_required
def video_feed():

    return Response(
        gen_frames(),
        mimetype="multipart/x-mixed-replace; boundary=frame"
    )


# ─── LOGIN ────────────────────────────────

@app.route("/api/login", methods=["POST"])
@block_if_locked
def api_login():

    ip_addr = get_real_ip()

    body = request.get_json(force=True, silent=True) or {}

    username = sanitise_username(body.get("username", ""))
    password = body.get("password", "").strip()[:128]

    if username is None:
        return jsonify({"success": False, "message": "Invalid username"}), 400

    success, result = verify_login(username, password)

    if success:

        clear_failed_logins(ip_addr)
        log_login_event(username, "Success", ip_address=ip_addr)

        session.clear()
        session["username"] = username
        session["role"]     = result
        session.permanent   = True

        return jsonify({
            "success":  True,
            "username": username,
            "role":     result
        })

    log_login_event(username, "Failed", result, ip_addr)

    rate = record_failed_login(ip_addr)

    if rate["blocked"]:

        register_threat(ip_addr, "Brute force detected")

        return jsonify({
            "success": False,
            "message": "IP blocked",
            "blocked": True
        }), 429

    return jsonify({
        "success":           False,
        "message":           result,
        "attempts_remaining": rate["remaining"]
    })


# ─── LOGOUT ────────────────────────────────

@app.route("/api/logout", methods=["POST"])
@login_required
def api_logout():

    username = session.get("username")
    ip_addr  = get_real_ip()

    log_login_event(username, "Logout", ip_address=ip_addr)
    session.clear()

    return jsonify({"success": True})


# ─── ADD USER ──────────────────────────────

@app.route("/api/add_user", methods=["POST"])
@admin_required
def api_add_user():

    body = request.get_json(force=True, silent=True) or {}

    new_username = sanitise_username(body.get("username", ""))
    password     = body.get("password", "").strip()

    if new_username is None:
        return jsonify({"success": False, "message": "Invalid username"}), 400

    if len(password) < 8:
        return jsonify({"success": False, "message": "Password too short"}), 400

    success, message = create_user(new_username, password)

    return jsonify({"success": success, "message": message})


# ─── STATS ─────────────────────────────────

@app.route("/api/stats")
@login_required
def api_stats():

    conn = None

    try:

        conn = db_connect()
        cur  = conn.cursor()

        cur.execute(
            "SELECT COUNT(*) FROM audit_logs WHERE status='Critical'"
        )
        critical = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM audit_logs")
        total = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM login_logs")
        logins = cur.fetchone()[0]

        cur.close()

        from security import get_blocked_ips
        blocked = len(get_blocked_ips())

        return jsonify({
            "critical": critical,
            "total":    total,
            "logins":   logins,
            "blocked":  blocked
        })

    except Exception:
        return jsonify({
            "critical": 0,
            "total":    0,
            "logins":   0,
            "blocked":  0
        })

    finally:
        if conn:
            conn.close()


# ─── SECURITY LOGS ─────────────────────────

@app.route("/api/logs")
@login_required
def api_logs():

    conn = None

    try:

        conn = db_connect()
        cur  = conn.cursor()

        cur.execute(
            """
            SELECT created_at, ip_address, action, status
            FROM audit_logs
            ORDER BY created_at DESC
            LIMIT 50
            """
        )

        rows = cur.fetchall()

        logs = [{
            "ts":   row[0].strftime("%Y-%m-%d %H:%M:%S") if row[0] else "",
            "ip":   row[1],
            "act":  row[2],
            "stat": row[3]
        } for row in rows]

        cur.close()

        return jsonify(logs)

    finally:
        if conn:
            conn.close()


# ─── AUTH / LOGIN LOGS ─────────────────────

@app.route("/api/login_logs")
@login_required
def api_login_logs():

    conn = None

    try:

        conn = db_connect()
        cur  = conn.cursor()

        cur.execute(
            """
            SELECT created_at, username, ip_address, status
            FROM login_logs
            ORDER BY created_at DESC
            LIMIT 50
            """
        )

        rows = cur.fetchall()

        logs = [{
            "ts":       row[0].strftime("%Y-%m-%d %H:%M:%S") if row[0] else "",
            "username": row[1],
            "ip":       row[2],
            "status":   row[3]
        } for row in rows]

        cur.close()

        return jsonify(logs)

    except Exception:
        return jsonify([])

    finally:
        if conn:
            conn.close()


# ─── THREATS ───────────────────────────────

@app.route("/api/threats")
@login_required
def api_threats():

    return jsonify(get_recent_threats())


# ─── BLOCKED IPs ───────────────────────────

@app.route("/api/blocked_ips")
@login_required
def api_blocked_ips():

    from security import get_blocked_ips
    return jsonify(get_blocked_ips())


@app.route("/api/blocked")
@admin_required
def api_blocked():

    from security import get_blocked_ips
    return jsonify(get_blocked_ips())


# ─── UNBLOCK IP ────────────────────────────

@app.route("/api/unblock_ip", methods=["POST"])
@admin_required
def api_unblock_ip():

    body = request.get_json(force=True, silent=True) or {}
    ip   = body.get("ip", "").strip()

    if not ip:
        return jsonify({"success": False, "message": "IP required"}), 400

    from security import unblock_ip
    unblock_ip(ip)

    return jsonify({"success": True})


# ─── GET USERS ─────────────────────────────

@app.route("/api/get_users")
@admin_required
def api_get_users():

    conn = None

    try:

        conn = db_connect()
        cur  = conn.cursor()

        cur.execute(
            """
            SELECT username, role, last_login, is_locked
            FROM users
            ORDER BY username
            """
        )

        rows = cur.fetchall()

        users = [{
            "username":    row[0],
            "role":        row[1],
            "last_active": row[2].strftime("%Y-%m-%d %H:%M") if row[2] else "Never",
            "status":      "Locked" if row[3] else "Active"
        } for row in rows]

        cur.close()

        return jsonify(users)

    except Exception:
        return jsonify([])

    finally:
        if conn:
            conn.close()


# ─── REVOKE USER ───────────────────────────

@app.route("/api/revoke_user", methods=["POST"])
@admin_required
def api_revoke_user():

    body     = request.get_json(force=True, silent=True) or {}
    username = sanitise_username(body.get("username", ""))

    if not username:
        return jsonify({"success": False, "message": "Invalid username"}), 400

    conn = None

    try:

        conn = db_connect()
        cur  = conn.cursor()

        cur.execute(
            "DELETE FROM users WHERE username=%s",
            (username,)
        )

        conn.commit()
        cur.close()

        return jsonify({"success": True, "message": "User revoked"})

    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

    finally:
        if conn:
            conn.close()


# ─── HEALTH CHECK ──────────────────────────

@app.route("/health")
def health():

    return jsonify({"status": "ok"})


# ─── START ─────────────────────────────────

if __name__ == "__main__":

    # Only import detector locally — scapy is not available on Railway
    if not os.getenv("RAILWAY_ENVIRONMENT_NAME"):
        from detector import start_detector

        detector_thread = threading.Thread(
            target=start_detector,
            daemon=True
        )
        detector_thread.start()

    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", 8080)),
        debug=False
    )