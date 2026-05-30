# Netad – Web-Based CCTV Security & Network Monitoring System

## System Screenshots & Diagram
- **[Network Architecture Diagram](./images/network_diagram.png)**
- **[Live Dashboard & CCTV Feed](./images/dashboard.png)**
- **[Security Logs & Login Screen](./images/login.png)**

---

## Project Structure

```text
netad/
├── .env                ← Supabase/Neon Database URL & Secrets (Keep private)
├── requirements.txt    ← Python dependencies
├── app.py              ← Main Flask Web Server & API Routes
├── auth.py             ← Authentication, Session & Hashing Logic
├── security.py         ← RBAC, Rate-Limiting, & SQLi Defense Layer
├── detector.py         ← Network intrusion monitor (Runs on background thread)
├── templates/          
│   ├── dashboard.html  ← Frontend UI (CCTV Feed & Audit Logs)
│   └── login.html      ← Secure Authentication Interface
└── security_alerts/    ← Auto-created, stores threat JPEG snapshots
```

---

## Setup Steps

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure your Environment Variables
Create a `.env` file in the root directory:
```ini
DATABASE_URL=postgresql://user:pass@host:port/dbname  # Use Supabase/Neon URL
SECRET_KEY=your_super_secret_flask_key_here
CCTV_URL=rtsp://192.168.1.10:554/stream1              # Or 0 for Local Webcam
```

### 3. Initialize the Database
Connect to your Cloud PostgreSQL provider (Neon/Supabase) and ensure your `users`, `login_logs`, and `audit_logs` tables are created. 

### 4. Run the Edge Node Server (Admin privileges required)
```bash
python app.py
```

### 5. Access the Dashboard
Open your browser and navigate to `http://localhost:8080`.

---

## Security & Authentication System
- **Password Hashing:** Accounts stored securely using SHA-256 + cryptographic salting.
- **Brute-Force Defense:** IPs are temporarily blocked after **5 failed attempts**.
- **Audit Trail:** Complete logging of Login/Logout timestamps, IP addresses, and Admin actions.
- **Role-Based Access Control (RBAC):** UI features restrict dynamically based on Admin vs. Operator roles.

## Physical Edge Camera Configuration
To switch between testing and production hardware, edit the `CAMERA_SRC` in `app.py`:
```python
CAMERA_SRC = 0                                        # Local USB Webcam testing
CAMERA_SRC = os.getenv("CCTV_URL")                    # Production PoE IP Camera
```
