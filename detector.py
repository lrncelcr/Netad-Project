import psycopg2
import os
import threading
from scapy.all import sniff, IP, ICMP, TCP, UDP
from datetime import datetime
from collections import defaultdict
from dotenv import load_dotenv

load_dotenv()
DB_URL = os.getenv("DATABASE_URL")

# ─── CONFIG ───────────────────────────────────────────────
CAMERA_IP            = "192.168.1.10"   # Target for professor's attack
PORT_SCAN_THRESHOLD  = 2                # Trigger Critical after only 2 ports
PING_FLOOD_THRESHOLD = 3                # Trigger Critical after only 3 pings
TRACKER_RESET_SEC    = 300              # Resets temporary counters every 5 mins
DB_PORT              = 31529            # Your Railway DB port (to avoid infinite loops)

# ─── STATE (thread-safe) ──────────────────────────────────
_lock              = threading.Lock()
port_scan_tracker  = defaultdict(set)   # {src_ip: {port, ...}}
ping_tracker       = defaultdict(list)  # {src_ip: [datetime, ...]}
udp_tracker        = defaultdict(set)   # {src_ip: {port, ...}}

# ─── DB LOGGING ───────────────────────────────────────────

def log_to_db(ip: str, action: str, status: str):
    """Log EVERY attempt to the database for full history."""
    try:
        conn = psycopg2.connect(DB_URL)
        cur  = conn.cursor()
        cur.execute(
            "INSERT INTO audit_logs (ip_address, action, status) VALUES (%s, %s, %s)",
            (ip, action, status)
        )
        conn.commit()
        cur.close()
        conn.close()
        
        # Console feedback for the demo
        print(f"🚨 ALERT: {status} | {action} from {ip}")
    except Exception as e:
        print(f"[DB ERROR] {e}")


# ─── PACKET HANDLERS ──────────────────────────────────────

def handle_icmp(src_ip: str, packet):
    if packet[ICMP].type != 8:
        return

    now = datetime.now()
    with _lock:
        pings = ping_tracker[src_ip]
        pings.append(now)
        ping_tracker[src_ip] = [t for t in pings if (now - t).seconds < 10]
        count = len(ping_tracker[src_ip])

    if count >= PING_FLOOD_THRESHOLD:
        log_to_db(src_ip, f"ICMP Flood Attack ({count} pings in 10 s)", "Critical")
    else:
        log_to_db(src_ip, "Unauthorized CCTV Ping Probe", "Alert")


def handle_tcp(src_ip: str, packet):
    flags = int(packet[TCP].flags)
    port  = packet[TCP].dport

    # SAFETY: Ignore traffic going to your database port to prevent self-logging
    if port == DB_PORT:
        return

    SYN = 0x002
    RST = 0x004
    FIN = 0x001

    if flags == SYN:
        with _lock:
            port_scan_tracker[src_ip].add(port)
            count = len(port_scan_tracker[src_ip])
            ports_list = sorted(port_scan_tracker[src_ip])

        if count >= PORT_SCAN_THRESHOLD:
            summary = str(ports_list[:8])[1:-1]
            log_to_db(src_ip, f"Port Scan ({count} ports: {summary})", "Critical")
            with _lock:
                port_scan_tracker[src_ip] = set()
        else:
            log_to_db(src_ip, f"Suspicious TCP SYN to Port {port}", "Alert")

    elif (flags & RST) and port in (554, 80, 8080, 443):
        log_to_db(src_ip, f"TCP RST to Camera Port {port}", "Alert")
    elif flags == FIN:
        log_to_db(src_ip, f"TCP FIN Scan to Port {port}", "Alert")
    elif flags == 0:
        log_to_db(src_ip, f"TCP NULL Scan to Port {port}", "Alert")
    elif flags & 0x029 == 0x029:
        log_to_db(src_ip, f"TCP XMAS Scan to Port {port}", "Critical")


def handle_udp(src_ip: str, packet):
    port = packet[UDP].dport
    with _lock:
        udp_tracker[src_ip].add(port)
        count = len(udp_tracker[src_ip])

    if count >= PORT_SCAN_THRESHOLD:
        log_to_db(src_ip, f"UDP Port Scan ({count} ports)", "Critical")
        with _lock:
            udp_tracker[src_ip] = set()
    else:
        log_to_db(src_ip, f"UDP Probe to Port {port}", "Alert")


# ─── MAIN CALLBACK ────────────────────────────────────────

def packet_callback(packet):
    if not packet.haslayer(IP):
        return
    if packet[IP].dst != CAMERA_IP:
        return

    src_ip = packet[IP].src
    if src_ip.startswith("127."):
        return

    if packet.haslayer(ICMP):
        handle_icmp(src_ip, packet)
    elif packet.haslayer(TCP):
        handle_tcp(src_ip, packet)
    elif packet.haslayer(UDP):
        handle_udp(src_ip, packet)


# ─── PERIODIC CLEANUP ─────────────────────────────────────

def _reset_trackers():
    with _lock:
        port_scan_tracker.clear()
        ping_tracker.clear()
        udp_tracker.clear()
    # Fixed: Uses the variable defined in CONFIG
    threading.Timer(TRACKER_RESET_SEC, _reset_trackers).start()


# ─── ENTRY POINT ──────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  🛡  Netad – Network Intrusion Detector")
    print(f"  Target Camera IP  :  {CAMERA_IP}")
    print(f"  Monitoring: ICMP | TCP | UDP")
    print("=" * 60)

    _reset_trackers()

    try:
        # Optimization: Filter out the database port at the sniffer level
        sniff_filter = f"(icmp or tcp or udp) and dst host {CAMERA_IP} and not port {DB_PORT}"
        sniff(filter=sniff_filter, prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\n[!] Detector stopped.")
    except PermissionError:
        print("\n[ERROR] Run as administrator to capture packets.")