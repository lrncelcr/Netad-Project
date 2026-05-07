"""
auth.py
───────
Authentication helpers: password hashing, login verification,
login event logging, and account lockout management.
"""
import psycopg2
import hashlib
import secrets
import socket
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()
DB_URL = os.getenv("DATABASE_URL")

# ─── CONSTANTS ────────────────────────────────────────────
MAX_FAILED_ATTEMPTS = 5   # Lock account after this many failures


# ─── UTILITIES ────────────────────────────────────────────

def get_local_ip() -> str:
    """Return the machine's primary LAN IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def hash_password(password: str, salt: str = None):
    """Hash password with SHA-256 + salt. Returns (hash, salt)."""
    if not salt:
        salt = secrets.token_hex(16)
    h = hashlib.sha256((password + salt).encode()).hexdigest()
    return h, salt

def db_connect():
    return psycopg2.connect(DB_URL)


# ─── AUTH FUNCTIONS ───────────────────────────────────────

def verify_login(username: str, password: str) -> tuple[bool, str]:
    """
    Check credentials against the DB.
    Returns (success: bool, message: str).
    """
    if not username or not password:
        return False, "Username and password are required."
    try:
        conn = db_connect()
        cur  = conn.cursor()
        cur.execute(
            "SELECT password_hash, salt, is_locked, failed_attempts, role FROM users WHERE username = %s",
            (username,)
        )
        row = cur.fetchone()
        cur.close()
        conn.close()

        if not row:
            return False, "User not found."

        stored_hash, salt, is_locked, failed, role = row

        if is_locked:
            return False, f"Account locked after {MAX_FAILED_ATTEMPTS} failed attempts. Contact admin."

        h, _ = hash_password(password, salt)
        if h == stored_hash:
            return True, role   # Return the user's role on success
        return False, "Invalid username or password."

    except Exception as e:
        return False, f"Database error: {e}"


def log_login_event(username: str, status: str, reason: str = ""):
    """
    Write a login attempt record and update failed-attempt counters.
    status: 'Success' | 'Failed'
    """
    ip = get_local_ip()
    try:
        conn = db_connect()
        cur  = conn.cursor()

        # Insert login record
        cur.execute(
            "INSERT INTO login_logs (username, ip_address, status, reason) VALUES (%s, %s, %s, %s)",
            (username, ip, status, reason)
        )

        if status == "Failed":
            # Increment failed counter and lock if threshold reached
            cur.execute(
                """
                UPDATE users
                SET failed_attempts = failed_attempts + 1,
                    is_locked = (failed_attempts + 1 >= %s)
                WHERE username = %s
                """,
                (MAX_FAILED_ATTEMPTS, username)
            )
        else:
            # Reset on success + record last login time
            cur.execute(
                "UPDATE users SET failed_attempts = 0, last_login = NOW(), is_locked = FALSE WHERE username = %s",
                (username,)
            )

        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[AUTH] Login log error: {e}")


def unlock_account(username: str) -> bool:
    """Admin utility: unlock a locked account and reset failure count."""
    try:
        conn = db_connect()
        cur  = conn.cursor()
        cur.execute(
            "UPDATE users SET is_locked = FALSE, failed_attempts = 0 WHERE username = %s",
            (username,)
        )
        conn.commit()
        cur.close()
        conn.close()
        return True
    except Exception as e:
        print(f"[AUTH] Unlock error: {e}")
        return False


def get_failed_attempts(username: str) -> int:
    """Return the current failed attempt count for a user."""
    try:
        conn = db_connect()
        cur  = conn.cursor()
        cur.execute("SELECT failed_attempts FROM users WHERE username = %s", (username,))
        row = cur.fetchone()
        cur.close()
        conn.close()
        return row[0] if row else 0
    except Exception:
        return 0
