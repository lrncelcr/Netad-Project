import psycopg2
from scapy.all import sniff, IP, ICMP, TCP, conf
from datetime import datetime

import os
from dotenv import load_dotenv

# Load the variables from the .env file
load_dotenv()

# Get the URL from the environment
DB_URL = os.getenv("DATABASE_URL")

def log_to_db(ip_addr, action, status):
    try:
        conn = psycopg2.connect(DB_URL)
        cur = conn.cursor()
        query = "INSERT INTO audit_logs (ip_address, action, status) VALUES (%s, %s, %s)"
        cur.execute(query, (ip_addr, action, status))
        conn.commit()
        cur.close()
        conn.close()
        print(f"[!] Logged: {action} from {ip_addr}")
    except Exception as e:
        print(f"[ERROR] Database logging failed: {e}")

def packet_callback(packet):
    # Detect Pings (ICMP)
    if packet.haslayer(ICMP):
        src_ip = packet[IP].src
        log_to_db(src_ip, "ICMP Network Scan", "Alert")

    # Detect TCP SYN Scans (The "Stealth" knock)
    elif packet.haslayer(TCP):
        if packet[TCP].flags == "S":  # 'S' is the SYN flag
            src_ip = packet[IP].src
            port = packet[TCP].dport
            log_to_db(src_ip, f"TCP SYN Scan (Port: {port})", "Critical")

print("--- Netad-Project: Monitoring ICMP and TCP Traffic ---")
sniff(filter="icmp or tcp", prn=packet_callback, store=0)