import os
import psycopg2
import hashlib
import secrets
from dotenv import load_dotenv

load_dotenv()

MAX_FAILED_ATTEMPTS = 5


def hash_password(password: str, salt: str = None):
    if not salt:
        salt = secrets.token_hex(16)

    h = hashlib.sha256(
        (password + salt).encode()
    ).hexdigest()

    return h, salt


def db_connect():

    db_url = os.getenv("DATABASE_URL")

    if db_url:
        return psycopg2.connect(db_url)

    return psycopg2.connect(
        host="localhost",
        database="netad_db",
        user="postgres",
        password="your_local_password"
    )


# ───── FUNCTION TO ADD USERS ─────

def create_user(username, password, role='Operator'):

    password_hash, salt = hash_password(password)

    conn = None

    try:
        conn = db_connect()
        cur = conn.cursor()

        cur.execute(
            """
            INSERT INTO users
            (
            username,
            password_hash,
            salt,
            role,
            failed_attempts,
            is_locked
            )
            VALUES
            (%s,%s,%s,%s,0,FALSE)
            """,
            (
                username,
                password_hash,
                salt,
                role
            )
        )

        conn.commit()

        cur.close()

        return True, "User created successfully."

    except Exception as e:
        return False, str(e)

    finally:
        if conn:
            conn.close()



def verify_login(username: str, password: str):

    if not username or not password:
        return False, "Username and password are required."

    conn = None

    try:

        conn = db_connect()
        cur = conn.cursor()

        cur.execute(
            """
            SELECT
            password_hash,
            salt,
            is_locked,
            failed_attempts,
            role
            FROM users
            WHERE username=%s
            """,
            (username,)
        )

        row = cur.fetchone()


        if not row:
            cur.close()
            return False, "User not found."


        stored_hash, salt, is_locked, failed, role = row


        if is_locked:
            cur.close()
            return False, "Account locked. Contact admin."


        h, _ = hash_password(password, salt)


        if h == stored_hash:

            # FIX:
            # reset failed attempts immediately
            cur.execute(
                """
                UPDATE users
                SET
                failed_attempts=0,
                is_locked=FALSE,
                last_login=NOW()
                WHERE username=%s
                """,
                (username,)
            )

            conn.commit()

            cur.close()

            return True, role


        cur.close()

        return False, "Invalid username or password."


    except Exception as e:

        return False, f"Database error: {e}"


    finally:

        if conn:
            conn.close()



def log_login_event(username, status, reason=None, ip_address='Unknown'):

    conn = None

    try:

        conn = db_connect()
        cur = conn.cursor()


        cur.execute(
            """
            INSERT INTO login_logs
            (username,ip_address,status,reason)
            VALUES (%s,%s,%s,%s)
            """,
            (
                username,
                ip_address,
                status,
                reason
            )
        )


        # FAILED LOGIN
        if status == "Failed":

            cur.execute(
                """
                UPDATE users
                SET
                failed_attempts = failed_attempts + 1,
                is_locked =
                CASE
                WHEN failed_attempts + 1 >= %s
                THEN TRUE
                ELSE FALSE
                END
                WHERE username=%s
                """,
                (
                    MAX_FAILED_ATTEMPTS,
                    username
                )
            )


        # SUCCESS LOGIN
        elif status == "Success":

            cur.execute(
                """
                UPDATE users
                SET
                failed_attempts=0,
                is_locked=FALSE,
                last_login=NOW()
                WHERE username=%s
                """,
                (username,)
            )


        # FIX:
        # Logout should NOT update last_login

        conn.commit()

        cur.close()


    except Exception as e:

        print(f"[AUTH ERROR] {e}")


    finally:

        if conn:
            conn.close()