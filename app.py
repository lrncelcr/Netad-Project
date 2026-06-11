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


# Get CCTV URL from .env
env_camera = os.getenv("CCTV_URL", "").strip()


# Disable camera on Railway
if (
    env_camera
    and env_camera.strip()
    and not os.getenv("RAILWAY_ENVIRONMENT")
):

    CAMERA_SRC = env_camera

    print(
        f"Using CCTV: {CAMERA_SRC}"
    )

else:

    CAMERA_SRC = None

    print(
        "Camera disabled"
    )



if CAMERA_SRC:

    cap = cv2.VideoCapture(
        CAMERA_SRC
    )

    cap.set(
        cv2.CAP_PROP_OPEN_TIMEOUT_MSEC,
        5000
    )

else:

    cap = None



if cap and not cap.isOpened():

    print(
        "Camera source not found"
    )

    cap = None




def gen_frames():

    while True:

        if cap is None:
            break


        success, frame = cap.read()


        if not success:

            print(
                "Failed to read camera frame"
            )

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


    body = request.get_json(
        force=True,
        silent=True
    ) or {}


    username = sanitise_username(
        body.get("username", "")
    )


    password = (
        body.get("password", "")
        .strip()[:128]
    )


    if username is None:

        return jsonify(
            {
                "success": False,
                "message": "Invalid username"
            }
        ), 400



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


        for row in rows:

            logs.append(
                {
                    "ts":
                    row[0].strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    if row[0] else "",

                    "ip": row[1],
                    "act": row[2],
                    "stat": row[3]
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


    # Disable detector on Railway
    if not os.getenv("RAILWAY_ENVIRONMENT"):

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