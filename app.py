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

from detector import start_detector

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
    SESSION_COOKIE_SECURE=os.getenv("FLASK_ENV") == "production",
    PERMANENT_SESSION_LIFETIME=3600,
    MAX_CONTENT_LENGTH=1024 * 1024
)


app.after_request(add_security_headers)



# ─── CAMERA ───────────────────────────────

ALERTS_DIR = "security_alerts"

os.makedirs(ALERTS_DIR, exist_ok=True)


env_camera = os.getenv("CCTV_URL")


if env_camera and env_camera.strip():
    CAMERA_SRC = env_camera
else:
    CAMERA_SRC = 0



cap = cv2.VideoCapture(CAMERA_SRC)


if not cap.isOpened():
    print("Camera source not found")



def gen_frames():

    while True:

        if cap is None or not cap.isOpened():
            break


        success, frame = cap.read()


        if not success:
            break


        _, buffer = cv2.imencode(
            ".jpg",
            frame,
            [
                cv2.IMWRITE_JPEG_QUALITY,
                75
            ]
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

            return jsonify(
                {
                    "error": "Unauthorized"
                }
            ), 401


        return f(*args, **kwargs)


    return decorated




def admin_required(f):

    @wraps(f)
    def decorated(*args, **kwargs):

        if not session.get("username"):

            return jsonify(
                {
                    "error": "Unauthorized"
                }
            ), 401


        role = str(
            session.get("role", "")
        ).lower()


        username = str(
            session.get("username", "")
        ).lower()



        if role != "admin" and username != "admin":

            return jsonify(
                {
                    "error": "Forbidden"
                }
            ), 403



        return f(*args, **kwargs)


    return decorated




# ─── ROUTES ────────────────────────────────

@app.route("/")
def index():

    if not session.get("username"):

        return render_template(
            "login.html"
        )


    return render_template(
        "dashboard.html"
    )



@app.route("/api/me")
@login_required
def api_me():

    return jsonify(
        {
            "username": session.get("username"),
            "role": session.get("role")
        }
    )



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


    if request.content_length and request.content_length > 4096:

        return jsonify(
            {
                "success": False,
                "message": "Request too large"
            }
        ), 413


    body = request.get_json(
        force=True,
        silent=True
    ) or {}


    username = sanitise_username(
        body.get("username", "")
    )


    if username is None:

        return jsonify(
            {
                "success": False,
                "message": "Invalid username"
            }
        ), 400


    password = (
        body.get("password", "")
        .strip()[:128]
    )


    success, result = verify_login(
        username,
        password
    )


    if success:

        clear_failed_logins(ip_addr)


        log_login_event(
            username,
            "Success",
            ip_address=ip_addr
        )


        session.clear()

        session["username"] = username
        session["role"] = result
        session.permanent = True


        return jsonify(
            {
                "success": True,
                "username": username,
                "role": result
            }
        )
        log_login_event(
        username,
        "Failed",
        result,
        ip_addr
    )


    rate = record_failed_login(
        ip_addr
    )


    if rate["blocked"]:

        register_threat(
            ip_addr,
            "Brute force detected"
        )


        return jsonify(
            {
                "success": False,
                "message": "IP blocked",
                "blocked": True
            }
        ), 429



    return jsonify(
        {
            "success": False,
            "message": result,
            "attempts_remaining": rate["remaining"]
        }
    )



# ─── LOGOUT ────────────────────────────────

@app.route("/api/logout", methods=["POST"])
@login_required
def api_logout():

    username = session.get("username")

    ip_addr = get_real_ip()


    log_login_event(
        username,
        "Logout",
        ip_address=ip_addr
    )


    session.clear()


    return jsonify(
        {
            "success": True
        }
    )




# ─── ADD USER ──────────────────────────────

@app.route("/api/add_user", methods=["POST"])
@admin_required
def api_add_user():

    body = request.get_json(
        force=True,
        silent=True
    ) or {}


    new_username = sanitise_username(
        body.get("username", "")
    )


    password = (
        body.get("password", "")
        .strip()
    )


    if new_username is None:

        return jsonify(
            {
                "success": False,
                "message": "Invalid username"
            }
        ), 400



    if len(password) < 8:

        return jsonify(
            {
                "success": False,
                "message": "Password too short"
            }
        ), 400



    success, message = create_user(
        new_username,
        password
    )



    if success:

        conn = None

        try:

            conn = db_connect()

            cur = conn.cursor()


            cur.execute(
                """
                INSERT INTO audit_logs
                (ip_address, action, status)
                VALUES (%s,%s,%s)
                """,
                (
                    get_real_ip(),
                    f"Created user {new_username}",
                    "Info"
                )
            )


            conn.commit()

            cur.close()


        finally:

            if conn:
                conn.close()



    return jsonify(
        {
            "success": success,
            "message": message
        }
    )




# ─── LOGS ──────────────────────────────────

@app.route("/api/logs")
@login_required
def api_logs():

    conn = None


    try:

        conn = db_connect()

        cur = conn.cursor()


        cur.execute(
            """
            SELECT
            created_at,
            ip_address,
            action,
            status
            FROM audit_logs
            ORDER BY created_at DESC
            LIMIT 50
            """
        )


        rows = cur.fetchall()


        logs = []


        for r in rows:

            logs.append(
                {
                    "ts":
                    r[0].strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    if r[0] else "",

                    "ip": r[1],
                    "act": r[2],
                    "stat": r[3]
                }
            )


        cur.close()


        return jsonify(logs)



    finally:

        if conn:
            conn.close()




# ─── THREATS ───────────────────────────────

@app.route("/api/threats")
@login_required
def api_threats():

    return jsonify(
        get_recent_threats()
    )




# ─── BLOCKED IPS ───────────────────────────

@app.route("/api/blocked")
@admin_required
def api_blocked():

    from security import get_blocked_ips


    return jsonify(
        get_blocked_ips()
    )




# ─── HEALTH CHECK ──────────────────────────

@app.route("/health")
def health():

    return jsonify(
        {
            "status": "ok"
        }
    )




# ─── START ─────────────────────────────────

if __name__ == "__main__":


    detector_thread = threading.Thread(
        target=start_detector,
        daemon=True
    )


    detector_thread.start()



    app.run(
        host="0.0.0.0",
        port=8080,
        debug=True
    )