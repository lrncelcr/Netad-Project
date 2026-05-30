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