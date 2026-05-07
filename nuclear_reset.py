import psycopg2, os
from dotenv import load_dotenv

load_dotenv()
DB_URL = os.getenv("DATABASE_URL")

try:
    conn = psycopg2.connect(DB_URL)
    cur = conn.cursor()
    
    print("🧹 Emptying Security Logs...")
    cur.execute("TRUNCATE TABLE audit_logs RESTART IDENTITY;")
    
    print("🔑 Emptying Login History...")
    cur.execute("TRUNCATE TABLE login_logs RESTART IDENTITY;")
    
    print("🔓 Resetting Account Lockouts...")
    cur.execute("UPDATE users SET failed_attempts = 0, is_locked = FALSE;")
    
    conn.commit() # This "Saves" the changes permanently
    print("✅ DATABASE IS NOW EMPTY.")
    
    cur.close()
    conn.close()
except Exception as e:
    print(f"❌ DATABASE ERROR: {e}")