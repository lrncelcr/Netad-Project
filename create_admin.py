import os

# 1. Force Python to use the Railway Cloud Database instead of the local .env file
os.environ['DATABASE_URL'] = "postgresql://postgres:ReDCtHWGIxIpoHMyvTWDqiLuDYRMJZOI@acela.proxy.rlwy.net:42726/railway"

# 2. Now import the auth function AFTER the environment variable is forced
from auth import create_user

def main():
    print("--- 🛡️ Setup Admin Account (Cloud Database) ---")
    username = input("Enter new admin username: ")
    password = input("Enter new admin password: ")
    
    # This calls your auth.py function and forces the role to 'Admin'
    success, message = create_user(username, password, role='Admin')
    
    if success:
        print(f"✅ Success! {message}")
        print("You can now log into your live Railway website.")
    else:
        print(f"❌ Error: {message}")

if __name__ == "__main__":
    main()