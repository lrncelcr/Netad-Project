import psycopg2
import hashlib
import secrets
import os
from dotenv import load_dotenv

load_dotenv()
DB_URL = os.getenv("DATABASE_URL")
MAX_FAILED_ATTEMPTS = 5 

def hash_password(password: str, salt: str = None):
    if not salt:
        salt = secrets.token_hex(16)
    h = hashlib.sha256((password + salt).encode()).hexdigest()
    return h, salt

def db_connect():
    return psycopg2.connect(DB_URL)

def verify_login(username: str, password: str) -> tuple[bool, str]:
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
        cur.close(); conn.close()

        if not row: return False, "User not found."

        stored_hash, salt, is_locked, failed, role = row
        if is_locked: return False, "Account locked. Contact admin."

        h, _ = hash_password(password, salt)
        if h == stored_hash: return True, role
        return False, "Invalid username or password."
    except Exception as e:
        return False, f"Database error: {e}"

def log_login_event(username, status, reason=None, ip_address='Unknown'):
    """Correctly handles logs and account lockouts without duplicate code."""
    try:
        conn = db_connect()
        cur = conn.cursor()

        # 1. Log the attempt
        cur.execute(
            "INSERT INTO login_logs (username, ip_address, status, reason) VALUES (%s, %s, %s, %s)",
            (username, ip_address, status, reason)
        )

        # 2. Lockout Logic
        if status == "Failed":
            cur.execute(
                """
                UPDATE users 
                SET failed_attempts = failed_attempts + 1,
                    is_locked = CASE WHEN (failed_attempts + 1) >= %s THEN TRUE ELSE FALSE END
                WHERE username = %s
                """,
                (MAX_FAILED_ATTEMPTS, username)
            )
        else:
            cur.execute(
                "UPDATE users SET failed_attempts = 0, is_locked = FALSE, last_login = NOW() WHERE username = %s",
                (username,)
            )

        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[AUTH ERROR] {e}")