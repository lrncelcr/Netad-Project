"""
security.py — Netad Hardened Security Layer
"""

import time
import threading
import html
import re

from collections import defaultdict
from functools import wraps
from typing import Optional

from flask import request, jsonify


# ─── CONFIGURATION ───────────────────────────────

LOGIN_RATE_WINDOW = 60

LOGIN_RATE_LIMIT = 8

BLOCK_DURATION = 300

BLOCK_THRESHOLD = 5



# ─── STATE ───────────────────────────────────────

_lock = threading.Lock()

_attempt_tracker = defaultdict(list)

_blocked_ips = {}

_threat_registry = []

MAX_REGISTRY_SIZE = 100




def _now():

    return time.time()



def _prune_attempts(ip):

    cutoff = _now() - LOGIN_RATE_WINDOW

    _attempt_tracker[ip] = [
        t for t in _attempt_tracker[ip]
        if t > cutoff
    ]




# ─── THREATS ─────────────────────────────────────


def register_threat(
    ip,
    reason,
    severity="Critical"
):

    with _lock:

        entry = {

            "ip": ip,

            "reason": reason,

            "severity": severity,

            "ts": time.strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        }


        _threat_registry.insert(
            0,
            entry
        )


        if len(_threat_registry) > MAX_REGISTRY_SIZE:

            _threat_registry.pop()





def get_recent_threats(limit=20):

    with _lock:

        return list(
            _threat_registry[:limit]
        )





# ─── BLOCK SYSTEM ────────────────────────────────


def is_ip_blocked(ip):

    with _lock:

        expiry = _blocked_ips.get(ip)


        if expiry is None:

            return False


        if _now() < expiry:

            return True


        del _blocked_ips[ip]

        return False





def block_ip(
    ip,
    duration=BLOCK_DURATION,
    reason="Brute force"
):

    with _lock:

        _blocked_ips[ip] = (
            _now() + duration
        )


    register_threat(
        ip,
        reason
    )


    print(
        f"[SECURITY] Blocked {ip}"
    )





def unblock_ip(ip):

    with _lock:

        _blocked_ips.pop(
            ip,
            None
        )





def get_blocked_ips():

    now = _now()

    with _lock:

        return {

            ip: int(exp-now)

            for ip,exp in _blocked_ips.items()

            if exp > now

        }






# ─── RATE LIMIT ──────────────────────────────────


def record_failed_login(ip):

    with _lock:

        _prune_attempts(ip)

        _attempt_tracker[ip].append(
            _now()
        )

        count = len(
            _attempt_tracker[ip]
        )


    if count >= BLOCK_THRESHOLD:

        block_ip(
            ip,
            BLOCK_DURATION,
            f"Brute force {count} attempts"
        )


        return {

            "blocked": True,

            "attempts": count,

            "remaining": 0
        }



    return {

        "blocked": False,

        "attempts": count,

        "remaining":
            BLOCK_THRESHOLD-count

    }





def clear_failed_logins(ip):

    with _lock:

        _attempt_tracker.pop(
            ip,
            None
        )






# ─── SANITIZATION ────────────────────────────────


_SAFE_USERNAME = re.compile(
    r'^[a-zA-Z0-9_\-\.]{1,64}$'
)



# FIX:
# compatible with Python 3.9+

def sanitise_username(
    raw: str
) -> Optional[str]:


    if not raw:

        return None


    cleaned = raw.strip()[:64]


    if not _SAFE_USERNAME.match(cleaned):

        return None


    return cleaned





def sanitise_text(
    raw,
    max_len=256
):

    if not raw:

        return ""


    return html.escape(
        raw.strip()[:max_len]
    )





# ─── IP DETECTION ─────────────────────────────────


def get_real_ip():

    forwarded = request.headers.get(
        "X-Forwarded-For",
        ""
    )


    if forwarded:

        ip = forwarded.split(",")[0].strip()


        if re.match(
            r'^\d{1,3}(\.\d{1,3}){3}$',
            ip
        ):

            return ip



    return request.remote_addr or "0.0.0.0"






# ─── DECORATOR ───────────────────────────────────


def block_if_locked(f):

    @wraps(f)

    def wrapped(*args, **kwargs):

        ip = get_real_ip()


        if is_ip_blocked(ip):

            remaining = int(
                _blocked_ips.get(
                    ip,
                    _now()
                ) - _now()
            )


            return jsonify({

                "success":False,

                "message":
                f"IP blocked. Retry {remaining}s",

                "blocked":True

            }),429



        return f(*args, **kwargs)


    return wrapped






# ─── SECURITY HEADERS ────────────────────────────


def add_security_headers(response):

    h = response.headers


    h["X-Content-Type-Options"] = "nosniff"


    h["X-Frame-Options"] = "DENY"


    h["X-XSS-Protection"] = "1; mode=block"


    h["Referrer-Policy"] = (
        "strict-origin-when-cross-origin"
    )


    h["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )


    h["Content-Security-Policy"] = (

        "default-src 'self'; "

        "script-src 'self' 'unsafe-inline' "
        "https://cdn.tailwindcss.com; "

        "style-src 'self' 'unsafe-inline' "
        "https://fonts.googleapis.com; "

        "font-src https://fonts.gstatic.com; "

        "img-src 'self' data: blob: https://*.trycloudflare.com *;"

    )


    if request.path.startswith("/api/"):

        h["Cache-Control"] = (
            "no-store, no-cache"
        )



    return response