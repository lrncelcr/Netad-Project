"""
security.py — Netad Hardened Security Layer
============================================
Drop-in module for app.py. Provides:
  • Server-side IP rate-limiting  (independent of client-side localStorage tricks)
  • Temporary IP block-list with auto-expiry
  • Input sanitisation helpers
  • Security response-header middleware
  • Real-time threat registry so the dashboard can surface live attack info
"""

import time
import threading
import html
import re
from collections import defaultdict
from functools import wraps
from flask import request, jsonify, session

# ─── CONFIGURATION ────────────────────────────────────────────────────────────
LOGIN_RATE_WINDOW   = 60      # seconds — sliding window for rate counting
LOGIN_RATE_LIMIT    = 8       # max login attempts per IP per window before soft-block
BLOCK_DURATION      = 300     # 5 minutes hard block after threshold breach
BLOCK_THRESHOLD     = 5       # failed attempts inside window that triggers a block

# ─── THREAD-SAFE STATE ────────────────────────────────────────────────────────
_lock              = threading.Lock()
_attempt_tracker   = defaultdict(list)   # ip  -> [unix_timestamp, ...]
_blocked_ips       = {}                  # ip  -> unblock_unix_timestamp
_threat_registry   = []                  # [{ip, reason, ts, severity}, …]  (last 100)
MAX_REGISTRY_SIZE  = 100


# ─── HELPERS ──────────────────────────────────────────────────────────────────

def _now() -> float:
    return time.time()


def _prune_attempts(ip: str):
    """Remove timestamps outside the sliding window (call while holding _lock)."""
    cutoff = _now() - LOGIN_RATE_WINDOW
    _attempt_tracker[ip] = [t for t in _attempt_tracker[ip] if t > cutoff]


def register_threat(ip: str, reason: str, severity: str = "Critical"):
    """
    Add an entry to the in-memory threat registry.
    Called by app.py whenever a security event occurs so the dashboard
    /api/threats endpoint can surface it immediately.
    """
    with _lock:
        entry = {"ip": ip, "reason": reason, "severity": severity,
                 "ts": time.strftime("%Y-%m-%d %H:%M:%S")}
        _threat_registry.insert(0, entry)
        # Keep list bounded
        if len(_threat_registry) > MAX_REGISTRY_SIZE:
            _threat_registry.pop()


def get_recent_threats(limit: int = 20) -> list:
    with _lock:
        return list(_threat_registry[:limit])


# ─── IP BLOCK LIST ────────────────────────────────────────────────────────────

def is_ip_blocked(ip: str) -> bool:
    """Returns True if IP is currently in the hard-block list."""
    with _lock:
        expiry = _blocked_ips.get(ip)
        if expiry is None:
            return False
        if _now() < expiry:
            return True
        # Expired — clean up
        del _blocked_ips[ip]
        return False


def block_ip(ip: str, duration: int = BLOCK_DURATION, reason: str = "Brute force"):
    """Add IP to the hard-block list and record the threat."""
    with _lock:
        _blocked_ips[ip] = _now() + duration
    register_threat(ip, reason)
    print(f"[SECURITY] 🔒 Blocked IP {ip} for {duration}s — {reason}")


def unblock_ip(ip: str):
    """Manually release an IP from the block list."""
    with _lock:
        _blocked_ips.pop(ip, None)


def get_blocked_ips() -> dict:
    """Return {ip: seconds_remaining} for all currently blocked IPs."""
    now = _now()
    with _lock:
        return {ip: int(exp - now) for ip, exp in _blocked_ips.items() if exp > now}


# ─── RATE LIMITER ─────────────────────────────────────────────────────────────

def record_failed_login(ip: str) -> dict:
    """
    Record a failed login attempt for ip.
    Returns: {"blocked": bool, "attempts": int, "remaining": int}
    """
    with _lock:
        _prune_attempts(ip)
        _attempt_tracker[ip].append(_now())
        count = len(_attempt_tracker[ip])

    if count >= BLOCK_THRESHOLD:
        block_ip(ip, BLOCK_DURATION,
                 f"Brute force: {count} failed logins in {LOGIN_RATE_WINDOW}s")
        return {"blocked": True, "attempts": count, "remaining": 0}

    remaining = max(0, BLOCK_THRESHOLD - count)
    return {"blocked": False, "attempts": count, "remaining": remaining}


def clear_failed_logins(ip: str):
    """Reset attempt counter on successful login."""
    with _lock:
        _attempt_tracker.pop(ip, None)


# ─── INPUT SANITISATION ───────────────────────────────────────────────────────

_SAFE_USERNAME = re.compile(r'^[a-zA-Z0-9_\-\.]{1,64}$')

def sanitise_username(raw: str) -> str | None:
    """
    Strip whitespace and validate username format.
    Returns cleaned string or None if invalid.
    """
    if not raw:
        return None
    cleaned = raw.strip()[:64]
    if not _SAFE_USERNAME.match(cleaned):
        return None
    return cleaned


def sanitise_text(raw: str, max_len: int = 256) -> str:
    """HTML-escape and truncate arbitrary text input."""
    if not raw:
        return ""
    return html.escape(raw.strip()[:max_len])


def get_real_ip() -> str:
    """
    Safely extract the real client IP, respecting X-Forwarded-For
    (set by Railway / reverse proxies) but not blindly trusting it.
    """
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        # Take only the leftmost (real client) address
        ip = forwarded.split(",")[0].strip()
        # Basic sanity — reject if it looks tampered
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip):
            return ip
    return request.remote_addr or "0.0.0.0"


# ─── DECORATORS ───────────────────────────────────────────────────────────────

def block_if_locked(f):
    """
    Route decorator — immediately reject requests from blocked IPs
    with a 429 before any DB or processing work happens.
    """
    @wraps(f)
    def wrapped(*args, **kwargs):
        ip = get_real_ip()
        if is_ip_blocked(ip):
            remaining = int(_blocked_ips.get(ip, _now()) - _now())
            return jsonify({
                "success": False,
                "message": f"IP temporarily blocked. Retry in {remaining}s.",
                "blocked": True
            }), 429
        return f(*args, **kwargs)
    return wrapped


# ─── SECURITY RESPONSE HEADERS ────────────────────────────────────────────────

def add_security_headers(response):
    """
    after_request hook — attach hardening headers to every response.
    Register with: app.after_request(add_security_headers)
    """
    h = response.headers

    # Prevent MIME sniffing
    h["X-Content-Type-Options"] = "nosniff"

    # Block clickjacking
    h["X-Frame-Options"] = "DENY"

    # Legacy XSS filter (belt + suspenders)
    h["X-XSS-Protection"] = "1; mode=block"

    # Control referrer leakage
    h["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Permissions policy — disable unnecessary browser features
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

    # CSP — tight policy; allow Tailwind CDN & Google Fonts used by the UI
    h["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' data: blob:; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )

    # Cache control for API responses
    if request.path.startswith("/api/"):
        h["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        h["Pragma"] = "no-cache"

    return response