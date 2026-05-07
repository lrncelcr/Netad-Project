# Netad – CCTV Security System

## Project Structure

```
netad/
├── .env                ← Database URL (keep private)
├── requirements.txt    ← Python dependencies
├── db_setup.sql        ← Run ONCE on your Railway DB
├── create_admin.py     ← Run ONCE to create login accounts
├── auth.py             ← Authentication helpers (imported by main.py)
├── main.py             ← Main GUI: Login + Dashboard
├── detector.py         ← Network intrusion monitor (run separately)
└── security_alerts/    ← Auto-created, stores JPEG snapshots
```

---

## Setup Steps

### 1. Install dependencies
```
pip install -r requirements.txt
```

### 2. Configure your .env
```
DATABASE_URL=postgresql://user:pass@host:port/dbname
```

### 3. Create database tables
Copy `db_setup.sql` into Railway's SQL console and run it.

### 4. Create your admin account
```
python create_admin.py
```

### 5. Run the dashboard
```
python main.py
```

### 6. Run the intrusion detector (separate terminal, as admin)
```
# Windows (run as Administrator):
python detector.py

# Linux/Mac:
sudo python detector.py
```

---

## Login System
- Accounts stored in `users` table with SHA-256 + salt hashing
- Account locked after **5 failed attempts**
- All login attempts logged to `login_logs` table
- Use `create_admin.py` to create or reset accounts

## Camera Source
Edit `CAMERA_SRC` in `main.py`:
```python
CAMERA_SRC = 0                                  # Webcam
CAMERA_SRC = "rtsp://192.168.1.10:554/stream1"  # IP Camera
```

## Detection Types (detector.py)
| Attack              | Detection Method             | Status   |
|---------------------|------------------------------|----------|
| Ping probe          | ICMP echo request            | Alert    |
| ICMP flood          | 10+ pings in 10 seconds      | Critical |
| Port scan (SYN)     | 5+ distinct SYN ports        | Critical |
| XMAS scan           | FIN+PSH+URG flag combo       | Critical |
| FIN / NULL scan     | FIN-only or 0-flag TCP       | Alert    |
| UDP port probe      | UDP to camera IP             | Alert    |
| RST flood           | RST to camera service ports  | Alert    |
