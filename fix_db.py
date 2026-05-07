import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()
DB_URL = os.getenv("DATABASE_URL")

def run_setup():
    try:
        # Read the SQL file
        with open("db_setup.sql", "r") as f:
            sql_commands = f.read()

        # Connect and execute
        conn = psycopg2.connect(DB_URL)
        cur = conn.cursor()
        print("🛠️ Connecting to Railway...")
        cur.execute(sql_commands)
        conn.commit()
        print("✅ Tables 'users' and 'login_logs' created successfully!")
        cur.close()
        conn.close()
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    run_setup()
    