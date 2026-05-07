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
# --- CONFIG ---
CAMERA_IP            = "192.168.1.10"   # Target for professor's attack
PORT_SCAN_THRESHOLD  = 2                # Trigger Critical after only 2 ports
PING_FLOOD_THRESHOLD = 3                # Trigger Critical after only 3 pings

# ─── STATE (thread-safe) ──────────────────────────────────
_lock              = threading.Lock()
port_scan_tracker  = defaultdict(set)   # {src_ip: {port, ...}}
ping_tracker       = defaultdict(list)  # {src_ip: [datetime, ...]}
udp_tracker        = defaultdict(set)   # {src_ip: {port, ...}}
logged_events      = set()             # Dedup key: (src_ip, action) to avoid spam


# ─── DB LOGGING ───────────────────────────────────────────

def log_to_db(ip: str, action: str, status: str):
    """Modified: Log EVERY attempt without 60s waiting period."""
    # Remove the 'with _lock' dedup block that starts here
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
        
        # This keeps your console bright and active during the demo
        print(f"🚨 ALERT: {status} | {action} from {ip}")
    except Exception as e:
        print(f"[DB ERROR] {e}")


# ─── PACKET HANDLERS ──────────────────────────────────────

def handle_icmp(src_ip: str, packet):
    """Detect ping probes and ICMP flood attacks."""
    if packet[ICMP].type != 8:   # Only echo requests
        return

    now = datetime.now()
    with _lock:
        pings = ping_tracker[src_ip]
        pings.append(now)
        # Keep only pings from the last 10 seconds
        ping_tracker[src_ip] = [t for t in pings if (now - t).seconds < 10]
        count = len(ping_tracker[src_ip])

    if count >= PING_FLOOD_THRESHOLD:
        log_to_db(src_ip, f"ICMP Flood Attack ({count} pings in 10 s)", "Critical")
    else:
        log_to_db(src_ip, "Unauthorized CCTV Ping Probe", "Alert")


def handle_tcp(src_ip: str, packet):
    """Detect SYN scans, targeted connections, and RST floods."""
    flags = int(packet[TCP].flags)
    port  = packet[TCP].dport

    SYN = 0x002
    RST = 0x004
    FIN = 0x001
    ACK = 0x010

    # SYN-only → port scan probe
    if flags == SYN:
        with _lock:
            port_scan_tracker[src_ip].add(port)
            count = len(port_scan_tracker[src_ip])
            ports_list = sorted(port_scan_tracker[src_ip])

        if count >= PORT_SCAN_THRESHOLD:
            summary = str(ports_list[:8])[1:-1]
            log_to_db(
                src_ip,
                f"Port Scan Detected ({count} ports: {summary}{'…' if count > 8 else ''})",
                "Critical"
            )
            with _lock:
                port_scan_tracker[src_ip] = set()  # Reset after logging
        else:
            log_to_db(src_ip, f"Suspicious TCP SYN to Port {port}", "Alert")

    # RST to camera port (possible DoS / connection teardown flood)
    elif (flags & RST) and port in (554, 80, 8080, 443):
        log_to_db(src_ip, f"TCP RST to Camera Port {port}", "Alert")

    # FIN scan (stealthy scan technique)
    elif flags == FIN:
        log_to_db(src_ip, f"TCP FIN Scan to Port {port}", "Alert")

    # NULL scan (all flags off)
    elif flags == 0:
        log_to_db(src_ip, f"TCP NULL Scan to Port {port}", "Alert")

    # XMAS scan (FIN+PSH+URG)
    elif flags & 0x029 == 0x029:
        log_to_db(src_ip, f"TCP XMAS Scan to Port {port}", "Critical")


def handle_udp(src_ip: str, packet):
    """Detect UDP port probing."""
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

    # Skip loopback
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
    """Clear stale port scan data periodically."""
    with _lock:
        port_scan_tracker.clear()
        ping_tracker.clear()
        udp_tracker.clear()
    print(f"\033[90m[{datetime.now().strftime('%H:%M:%S')}] Tracker state cleared.\033[0m")
    threading.Timer(TRACKER_RESET_SEC, _reset_trackers).start()


# ─── ENTRY POINT ──────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  🛡  Netad – Network Intrusion Detector")
    print(f"  Target Camera IP  :  {CAMERA_IP}")
    print(f"  Port scan threshold: {PORT_SCAN_THRESHOLD} ports")
    print(f"  Ping flood threshold: {PING_FLOOD_THRESHOLD} pings/10s")
    print("  Monitoring: ICMP | TCP | UDP")
    print("=" * 60)
    print("  Press Ctrl+C to stop.\n")

    _reset_trackers()

    try:
        sniff(
            filter=f"(icmp or tcp or udp) and dst host {CAMERA_IP}",
            prn=packet_callback,
            store=0
        )
    except KeyboardInterrupt:
        print("\n\033[93m[!] Detector stopped.\033[0m")
    except PermissionError:
        print("\n\033[91m[ERROR] Run as administrator/root to capture packets.\033[0m")
