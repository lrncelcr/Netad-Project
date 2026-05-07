"""
create_admin.py
───────────────
Run this ONCE after db_setup.sql to create the default admin account.
Usage:  python create_admin.py
"""
import psycopg2
import hashlib
import secrets
import getpass
import os
from dotenv import load_dotenv

load_dotenv()
DB_URL = os.getenv("DATABASE_URL")

def hash_password(password: str, salt: str = None):
    if not salt:
        salt = secrets.token_hex(16)
    h = hashlib.sha256((password + salt).encode()).hexdigest()
    return h, salt

def create_user(username: str, password: str, role: str = "admin"):
    h, salt = hash_password(password)
    try:
        conn = psycopg2.connect(DB_URL)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO users (username, password_hash, salt, role)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (username) DO UPDATE
                SET password_hash = EXCLUDED.password_hash,
                    salt          = EXCLUDED.salt,
                    role          = EXCLUDED.role,
                    is_locked     = FALSE,
                    failed_attempts = 0
            """,
            (username, h, salt, role)
        )
        conn.commit()
        cur.close()
        conn.close()
        print(f"\n✅  User '{username}' ({role}) created / updated successfully.")
    except Exception as e:
        print(f"\n❌  Error: {e}")

if __name__ == "__main__":
    print("=" * 45)
    print("  Netad – Create / Reset User Account")
    print("=" * 45)
    uname = input("Username [admin]: ").strip() or "admin"
    role  = input("Role (admin/viewer) [admin]: ").strip() or "admin"
    pwd   = getpass.getpass("Password: ")
    pwd2  = getpass.getpass("Confirm Password: ")

    if pwd != pwd2:
        print("❌  Passwords do not match.")
    elif len(pwd) < 6:
        print("❌  Password must be at least 6 characters.")
    else:
        create_user(uname, pwd, role)
