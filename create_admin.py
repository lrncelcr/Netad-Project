from auth import create_user

def main():
    print("--- 🛡️ Setup Admin Account ---")
    username = input("Enter new admin username: ")
    password = input("Enter new admin password: ")

    # This calls your auth.py function and forces the role to 'Admin'
    success, message = create_user(username, password, role='Admin')

    if success:
        print(f"✅ Success! {message}")
        print("You can now start app.py and log into your dashboard.")
    else:
        print(f"❌ Error: {message}")

if __name__ == "__main__":
    main()