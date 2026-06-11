import psycopg2
import os
import threading

from scapy.all import sniff, IP, ICMP, TCP, UDP
from datetime import datetime
from collections import defaultdict
from dotenv import load_dotenv


load_dotenv()

DB_URL = os.getenv("DATABASE_URL")

if not DB_URL:
    raise RuntimeError("DATABASE_URL is missing")


# ─── CONFIG ───────────────────────────────────────────────

CAMERA_IP = "192.168.100.7"

PORT_SCAN_THRESHOLD = 2
PING_FLOOD_THRESHOLD = 3

TRACKER_RESET_SEC = 300

DB_PORT = 31529


# ─── STATE ────────────────────────────────────────────────

_lock = threading.Lock()

port_scan_tracker = defaultdict(set)
ping_tracker = defaultdict(list)
udp_tracker = defaultdict(set)

# ─── DB LOGGING ───────────────────────────────────────────

def log_to_db(ip: str, action: str, status: str):

    conn = None

    try:

        conn = psycopg2.connect(DB_URL)

        cur = conn.cursor()

        cur.execute(
            """
            INSERT INTO audit_logs
            (ip_address, action, status)
            VALUES (%s, %s, %s)
            """,
            (
                ip,
                action,
                status
            )
        )

        conn.commit()

        cur.close()

        print(
            f"🚨 ALERT: {status} | {action} from {ip}"
        )


    except Exception as e:

        print(f"[DB ERROR] {e}")


    finally:

        if conn:
            conn.close()



# ─── PACKET HANDLERS ──────────────────────────────────────

def handle_icmp(src_ip, packet):

    if packet[ICMP].type != 8:
        return


    now = datetime.now()


    with _lock:

        ping_tracker[src_ip].append(now)

        ping_tracker[src_ip] = [
            t for t in ping_tracker[src_ip]
            if (now - t).seconds < 10
        ]

        count = len(
            ping_tracker[src_ip]
        )


    if count >= PING_FLOOD_THRESHOLD:

        log_to_db(
            src_ip,
            f"ICMP Flood Attack ({count} pings in 10s)",
            "Critical"
        )

    else:

        log_to_db(
            src_ip,
            "Unauthorized CCTV Ping Probe",
            "Alert"
        )



def handle_tcp(src_ip, packet):

    flags = int(packet[TCP].flags)

    port = packet[TCP].dport


    if port == DB_PORT:
        return


    SYN = 0x002
    RST = 0x004
    FIN = 0x001


    if flags == SYN:

        with _lock:

            port_scan_tracker[src_ip].add(port)

            count = len(
                port_scan_tracker[src_ip]
            )

            ports = sorted(
                port_scan_tracker[src_ip]
            )


        if count >= PORT_SCAN_THRESHOLD:

            log_to_db(
                src_ip,
                f"Port Scan ({count} ports: {ports[:8]})",
                "Critical"
            )


            with _lock:

                port_scan_tracker[src_ip].clear()


        else:

            log_to_db(
                src_ip,
                f"Suspicious TCP SYN to Port {port}",
                "Alert"
            )


    elif (flags & RST) and port in (554, 80, 8080, 443):

        log_to_db(
            src_ip,
            f"TCP RST to Camera Port {port}",
            "Alert"
        )


    elif flags == FIN:

        log_to_db(
            src_ip,
            f"TCP FIN Scan to Port {port}",
            "Alert"
        )


    elif flags == 0:

        log_to_db(
            src_ip,
            f"TCP NULL Scan to Port {port}",
            "Alert"
        )


    elif (flags & 0x029) == 0x029:

        log_to_db(
            src_ip,
            f"TCP XMAS Scan to Port {port}",
            "Critical"
        )



def handle_udp(src_ip, packet):

    port = packet[UDP].dport


    with _lock:

        udp_tracker[src_ip].add(port)

        count = len(
            udp_tracker[src_ip]
        )


    if count >= PORT_SCAN_THRESHOLD:

        log_to_db(
            src_ip,
            f"UDP Port Scan ({count} ports)",
            "Critical"
        )


        with _lock:

            udp_tracker[src_ip].clear()


    else:

        log_to_db(
            src_ip,
            f"UDP Probe to Port {port}",
            "Alert"
        )



# ─── CALLBACK ─────────────────────────────────────────────

def packet_callback(packet):

    if not packet.haslayer(IP):
        return


    if packet[IP].dst != CAMERA_IP:
        return


    src_ip = packet[IP].src


    if src_ip.startswith("127."):
        return


    if packet.haslayer(ICMP):

        handle_icmp(
            src_ip,
            packet
        )


    elif packet.haslayer(TCP):

        handle_tcp(
            src_ip,
            packet
        )


    elif packet.haslayer(UDP):

        handle_udp(
            src_ip,
            packet
        )



# ─── CLEANUP ──────────────────────────────────────────────

def _reset_trackers():

    with _lock:

        port_scan_tracker.clear()
        ping_tracker.clear()
        udp_tracker.clear()


    threading.Timer(
        TRACKER_RESET_SEC,
        _reset_trackers
    ).start()



# ─── START ────────────────────────────────────────────────

def start_detector():

    print("=" * 60)
    print("🛡 Netad – Network Intrusion Detector ACTIVE")
    print(f"Target Camera IP: {CAMERA_IP}")
    print("=" * 60)


    _reset_trackers()


    try:

        sniff_filter = (
            f"(icmp or tcp or udp) "
            f"and dst host {CAMERA_IP} "
            f"and not port {DB_PORT}"
        )


        sniff(
            filter=sniff_filter,
            prn=packet_callback,
            store=0
        )


    except Exception as e:

        print(
            f"[DETECTOR ERROR] {e}"
        )



if __name__ == "__main__":

    start_detector()