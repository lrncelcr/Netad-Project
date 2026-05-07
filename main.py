"""
main.py
───────
Netad CCTV Security System — Main Application
Includes: Login screen → Security Dashboard (camera + logs + stats)
"""
import customtkinter as ctk
import cv2
import os
from PIL import Image, ImageTk
from datetime import datetime
from dotenv import load_dotenv
import psycopg2
import tkinter as tk

from auth import verify_login, log_login_event, get_failed_attempts, MAX_FAILED_ATTEMPTS, db_connect

load_dotenv()

# ─── CONFIG ───────────────────────────────────────────────
ALERTS_DIR  = "security_alerts"
CAMERA_SRC  = 0          # 0 = webcam. Replace with RTSP URL string for IP cam
                          # e.g. "rtsp://192.168.1.10:554/stream1"
os.makedirs(ALERTS_DIR, exist_ok=True)

# ─── THEME ────────────────────────────────────────────────
COL_BG       = "#0A0A0A"
COL_PANEL    = "#111111"
COL_BORDER   = "#1E1E1E"
COL_GREEN    = "#2ECC71"
COL_RED      = "#E74C3C"
COL_YELLOW   = "#F39C12"
COL_BLUE     = "#3498DB"
COL_MUTED    = "#555555"
COL_TEXT     = "#CCCCCC"

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")


# ═══════════════════════════════════════════════════════════
#  LOGIN FRAME
# ═══════════════════════════════════════════════════════════

class LoginFrame(ctk.CTkFrame):
    def __init__(self, master: "NetadApp"):
        super().__init__(master, fg_color=COL_BG)
        self.master = master
        self._fail_count = 0
        self._locked = False
        self._build()

    def _build(self):
        # ── Background gradient panel ──
        outer = ctk.CTkFrame(self, fg_color=COL_BG)
        outer.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.85, relheight=0.90)

        # Logo section
        ctk.CTkLabel(outer, text="🔒", font=("Segoe UI Emoji", 56)).pack(pady=(40, 4))
        ctk.CTkLabel(outer, text="NETAD", font=("Inter", 32, "bold"),
                     text_color=COL_GREEN).pack()
        ctk.CTkLabel(outer, text="CCTV Security Management System",
                     font=("Inter", 11), text_color=COL_MUTED).pack(pady=(2, 28))

        # Card
        card = ctk.CTkFrame(outer, fg_color=COL_PANEL, corner_radius=14,
                            border_width=1, border_color=COL_BORDER)
        card.pack(padx=30, fill="x")

        ctk.CTkLabel(card, text="Sign In", font=("Inter", 18, "bold"),
                     text_color=COL_TEXT).pack(pady=(22, 16))

        # Username
        ctk.CTkLabel(card, text="Username", font=("Inter", 11),
                     text_color=COL_MUTED, anchor="w").pack(padx=28, fill="x")
        self._uname = ctk.CTkEntry(card, height=40, placeholder_text="Enter your username",
                                   font=("Inter", 13), border_color=COL_BORDER,
                                   fg_color="#1A1A1A")
        self._uname.pack(padx=28, pady=(3, 10), fill="x")

        # Password
        ctk.CTkLabel(card, text="Password", font=("Inter", 11),
                     text_color=COL_MUTED, anchor="w").pack(padx=28, fill="x")
        self._pwd = ctk.CTkEntry(card, height=40, placeholder_text="Enter your password",
                                 show="●", font=("Inter", 13), border_color=COL_BORDER,
                                 fg_color="#1A1A1A")
        self._pwd.pack(padx=28, pady=(3, 6), fill="x")
        self._pwd.bind("<Return>", lambda _: self._attempt())

        # Error label
        self._err = ctk.CTkLabel(card, text="", font=("Inter", 11),
                                  text_color=COL_RED, wraplength=280)
        self._err.pack(pady=(4, 0))

        # Attempt counter bar
        self._attempt_bar = ctk.CTkProgressBar(card, height=4, fg_color="#222",
                                               progress_color=COL_RED)
        self._attempt_bar.set(0)
        self._attempt_bar.pack(padx=28, pady=(6, 0), fill="x")

        # Login button
        self._btn = ctk.CTkButton(
            card, text="SIGN IN", height=44,
            font=("Inter", 13, "bold"),
            fg_color=COL_GREEN, hover_color="#27AE60", text_color="#000",
            corner_radius=8, command=self._attempt
        )
        self._btn.pack(padx=28, pady=(14, 22), fill="x")

        # Footer
        ctk.CTkLabel(outer,
                     text="⚠  Unauthorized access is prohibited and actively monitored.",
                     font=("Inter", 9), text_color="#444").pack(pady=(14, 0))

    # ── Logic ──────────────────────────────────────────

    def _attempt(self):
        if self._locked:
            return
        u = self._uname.get().strip()
        p = self._pwd.get().strip()
        if not u or not p:
            self._show_error("Please fill in all fields.")
            return
        self._btn.configure(state="disabled", text="Verifying…")
        self.after(150, lambda: self._do_login(u, p))

    def _do_login(self, username: str, password: str):
        success, result = verify_login(username, password)

        if success:
            log_login_event(username, "Success")
            self.master.show_dashboard(username, role=result)
        else:
            self._fail_count += 1
            log_login_event(username, "Failed", result)
            remaining = MAX_FAILED_ATTEMPTS - get_failed_attempts(username)
            remaining = max(0, remaining)

            if "locked" in result.lower():
                self._locked = True
                self._show_error(f"🔒 {result}")
                self._btn.configure(state="disabled", text="ACCOUNT LOCKED")
            else:
                msg = f"✗  {result}"
                if remaining <= 2:
                    msg += f"\n⚠  {remaining} attempt(s) remaining before lockout."
                self._show_error(msg)
                self._btn.configure(state="normal", text="SIGN IN")
                self._attempt_bar.set(self._fail_count / MAX_FAILED_ATTEMPTS)
                self._shake()

    def _show_error(self, msg: str):
        self._err.configure(text=msg)

    def _shake(self):
        x, y = self.master.winfo_x(), self.master.winfo_y()
        for i, dx in enumerate([8, -8, 6, -6, 4, -4, 0]):
            self.master.after(i * 40, lambda d=dx: self.master.geometry(f"+{x+d}+{y}"))


# ═══════════════════════════════════════════════════════════
#  DASHBOARD FRAME
# ═══════════════════════════════════════════════════════════

class DashboardFrame(ctk.CTkFrame):
    def __init__(self, master: "NetadApp", username: str, role: str):
        super().__init__(master, fg_color=COL_BG)
        self.master        = master
        self.username      = username
        self.role          = role
        self._last_snap_ts = None
        self._rec_visible  = True
        self._build()
        self._start()

    # ── UI Construction ────────────────────────────────

    def _build(self):
        self._build_header()
        self._build_stats()
        self._build_content()

    def _build_header(self):
        bar = ctk.CTkFrame(self, fg_color=COL_PANEL, height=52, corner_radius=0,
                           border_width=0)
        bar.pack(fill="x")
        bar.pack_propagate(False)

        left = ctk.CTkFrame(bar, fg_color="transparent")
        left.pack(side="left", padx=14, pady=8)
        ctk.CTkLabel(left, text="🛡  NETAD", font=("Inter", 17, "bold"),
                     text_color=COL_GREEN).pack(side="left")
        ctk.CTkLabel(left, text=" – CCTV Security Dashboard",
                     font=("Inter", 12), text_color=COL_MUTED).pack(side="left")

        right = ctk.CTkFrame(bar, fg_color="transparent")
        right.pack(side="right", padx=14)

        self._clock_lbl = ctk.CTkLabel(right, text="", font=("Consolas", 11),
                                        text_color=COL_MUTED)
        self._clock_lbl.pack(side="left", padx=(0, 18))

        ctk.CTkLabel(right, text=f"👤 {self.username}",
                     font=("Inter", 11, "bold"), text_color=COL_TEXT).pack(side="left", padx=(0, 8))
        ctk.CTkLabel(right, text=f"[{self.role.upper()}]",
                     font=("Inter", 9), text_color=COL_MUTED).pack(side="left", padx=(0, 14))

        ctk.CTkButton(right, text="⏻  Logout", width=85, height=30,
                      font=("Inter", 11), fg_color="#2A2A2A",
                      hover_color=COL_RED, text_color=COL_TEXT,
                      command=self._logout).pack(side="left")

    def _build_stats(self):
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=(10, 6))

        self._s_critical  = self._stat_card(row, "0",      "CRITICAL EVENTS",  COL_RED)
        self._s_alerts    = self._stat_card(row, "0",      "TOTAL EVENTS",      COL_YELLOW)
        self._s_logins    = self._stat_card(row, "0",      "LOGIN ATTEMPTS",    COL_BLUE)
        self._s_failed    = self._stat_card(row, "0",      "FAILED LOGINS",     COL_RED)
        self._s_snapshots = self._stat_card(row, "0",      "ALERT SNAPSHOTS",   COL_MUTED)
        self._s_status    = self._stat_card(row, "ARMED",  "SYSTEM STATUS",     COL_GREEN)

    def _stat_card(self, parent, value, label, color):
        f = ctk.CTkFrame(parent, fg_color=COL_PANEL, corner_radius=10,
                         border_width=1, border_color=COL_BORDER)
        f.pack(side="left", fill="x", expand=True, padx=4)
        v = ctk.CTkLabel(f, text=value, font=("Inter", 22, "bold"), text_color=color)
        v.pack(pady=(12, 2))
        ctk.CTkLabel(f, text=label, font=("Inter", 8, "bold"),
                     text_color=COL_MUTED).pack(pady=(0, 12))
        return v

    def _build_content(self):
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=14, pady=(0, 10))

        # ── LEFT: Camera ──
        left = ctk.CTkFrame(body, fg_color="transparent")
        left.pack(side="left", fill="both", expand=True, padx=(0, 8))

        cam_bar = ctk.CTkFrame(left, fg_color=COL_PANEL, corner_radius=8, height=36,
                               border_width=1, border_color=COL_BORDER)
        cam_bar.pack(fill="x", pady=(0, 5))
        cam_bar.pack_propagate(False)
        ctk.CTkLabel(cam_bar, text="📷  LIVE FEED — CAM 01",
                     font=("Inter", 12, "bold"), text_color=COL_GREEN).pack(side="left", padx=12, pady=8)
        self._rec_lbl = ctk.CTkLabel(cam_bar, text="⬤ REC",
                                      font=("Inter", 10, "bold"), text_color=COL_RED)
        self._rec_lbl.pack(side="right", padx=12)

        self._vid = ctk.CTkLabel(left, text="⚠  No Camera Signal",
                                  fg_color=COL_PANEL, corner_radius=8,
                                  font=("Inter", 14), text_color=COL_MUTED)
        self._vid.pack(fill="both", expand=True)

        # ── RIGHT: Logs ──
        right = ctk.CTkFrame(body, fg_color="transparent", width=380)
        right.pack(side="right", fill="both")
        right.pack_propagate(False)

        # Security Events log
        self._sec_log = self._log_panel(
            right,
            title="🚨  Security Events",
            height=0,           # will expand
        )
        self._sec_log.pack(fill="both", expand=True, pady=(0, 6))

        # Login History log
        self._login_log = self._log_panel(
            right,
            title="🔑  Login History",
            height=0,
        )
        self._login_log.pack(fill="both", expand=True)

        # Refresh button
        ctk.CTkButton(right, text="↻  Refresh Now", height=32,
                      font=("Inter", 11), fg_color="#1E1E1E",
                      hover_color=COL_GREEN, text_color=COL_TEXT,
                      command=self._fetch_all).pack(fill="x", pady=(6, 0))

    def _log_panel(self, parent, title: str, height: int):
        """Build a labeled log panel and return the inner Text widget."""
        wrap = ctk.CTkFrame(parent, fg_color=COL_PANEL, corner_radius=8,
                            border_width=1, border_color=COL_BORDER)

        hdr = ctk.CTkFrame(wrap, fg_color="#161616", height=30, corner_radius=0)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text=title, font=("Inter", 11, "bold"),
                     text_color=COL_TEXT).pack(side="left", padx=10, pady=5)

        # Use raw tk.Text for colored log entries
        txt = tk.Text(wrap, bg="#0E0E0E", fg=COL_TEXT,
                      font=("Consolas", 10), relief="flat",
                      bd=0, padx=8, pady=6, wrap="word",
                      state="disabled", cursor="arrow")
        txt.pack(fill="both", expand=True, padx=1, pady=(0, 1))

        # Color tags
        txt.tag_config("critical", foreground=COL_RED)
        txt.tag_config("alert",    foreground=COL_YELLOW)
        txt.tag_config("info",     foreground=COL_BLUE)
        txt.tag_config("success",  foreground=COL_GREEN)
        txt.tag_config("failed",   foreground=COL_RED)
        txt.tag_config("dim",      foreground=COL_MUTED)
        txt.tag_config("bold",     font=("Consolas", 10, "bold"))

        return wrap, txt  # Return both the frame and the text widget

    def _log_panel(self, parent, title: str, height: int):
        wrap = ctk.CTkFrame(parent, fg_color=COL_PANEL, corner_radius=8,
                            border_width=1, border_color=COL_BORDER)

        hdr = ctk.CTkFrame(wrap, fg_color="#161616", height=30, corner_radius=0)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text=title, font=("Inter", 11, "bold"),
                     text_color=COL_TEXT).pack(side="left", padx=10, pady=5)

        txt = tk.Text(wrap, bg="#0E0E0E", fg=COL_TEXT,
                      font=("Consolas", 10), relief="flat",
                      bd=0, padx=8, pady=6, wrap="word",
                      state="disabled", cursor="arrow")
        txt.pack(fill="both", expand=True, padx=1, pady=(0, 1))

        txt.tag_config("critical",  foreground=COL_RED)
        txt.tag_config("alert",     foreground=COL_YELLOW)
        txt.tag_config("info",      foreground=COL_BLUE)
        txt.tag_config("success",   foreground=COL_GREEN)
        txt.tag_config("failed",    foreground="#FF6B6B")
        txt.tag_config("dim",       foreground=COL_MUTED)
        txt.tag_config("timestamp", foreground="#666")

        return wrap, txt

    def _build_content(self):
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=14, pady=(0, 10))

        # LEFT: Camera
        left = ctk.CTkFrame(body, fg_color="transparent")
        left.pack(side="left", fill="both", expand=True, padx=(0, 8))

        cam_bar = ctk.CTkFrame(left, fg_color=COL_PANEL, corner_radius=8, height=36,
                               border_width=1, border_color=COL_BORDER)
        cam_bar.pack(fill="x", pady=(0, 5))
        cam_bar.pack_propagate(False)
        ctk.CTkLabel(cam_bar, text="📷  LIVE FEED — CAM 01",
                     font=("Inter", 12, "bold"), text_color=COL_GREEN).pack(side="left", padx=12)
        self._rec_lbl = ctk.CTkLabel(cam_bar, text="⬤ REC",
                                      font=("Inter", 10, "bold"), text_color=COL_RED)
        self._rec_lbl.pack(side="right", padx=12)

        self._vid = ctk.CTkLabel(left, text="⚠  No Camera Signal",
                                  fg_color=COL_PANEL, corner_radius=8,
                                  font=("Inter", 14), text_color=COL_MUTED)
        self._vid.pack(fill="both", expand=True)

        # RIGHT: Logs
        right = ctk.CTkFrame(body, fg_color="transparent", width=390)
        right.pack(side="right", fill="both")
        right.pack_propagate(False)

        _, self._sec_txt = self._log_panel(right, "🚨  Security Events", 0)
        _.pack(fill="both", expand=True, pady=(0, 6))

        _, self._login_txt = self._log_panel(right, "🔑  Login History", 0)
        _.pack(fill="both", expand=True)

        ctk.CTkButton(right, text="↻  Refresh Now", height=32,
                      font=("Inter", 11), fg_color="#1E1E1E",
                      hover_color=COL_GREEN, text_color=COL_TEXT,
                      command=self._fetch_all).pack(fill="x", pady=(6, 0))

    # ── Runtime ────────────────────────────────────────

    def _start(self):
        self._update_frame()
        self._blink_rec()
        self._tick_clock()
        self._fetch_all()
        self._auto_refresh()

    def _update_frame(self):
        cap = self.master.cap
        if cap and cap.isOpened():
            ret, frame = cap.read()
            if ret:
                rgb  = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                img  = Image.fromarray(rgb).resize((640, 380))
                itk  = ImageTk.PhotoImage(image=img)
                self._vid.imgtk = itk
                self._vid.configure(image=itk, text="")
        self._vid.after(15, self._update_frame)

    def _blink_rec(self):
        self._rec_visible = not self._rec_visible
        col = COL_RED if self._rec_visible else "#2A0A0A"
        self._rec_lbl.configure(text_color=col)
        self.after(700, self._blink_rec)

    def _tick_clock(self):
        self._clock_lbl.configure(text=datetime.now().strftime("%Y-%m-%d   %H:%M:%S"))
        self.after(1000, self._tick_clock)

    def _auto_refresh(self):
        self._fetch_all()
        self.after(5000, self._auto_refresh)

    # ── Data Fetching ──────────────────────────────────

    def _fetch_all(self):
        self._fetch_security_logs()
        self._fetch_login_logs()
        self._fetch_stats()

    def _write_log(self, widget: tk.Text, lines: list):
        """lines = list of (text, tag) tuples"""
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        for text, tag in lines:
            if tag:
                widget.insert("end", text, tag)
            else:
                widget.insert("end", text)
        widget.configure(state="disabled")

    def _fetch_security_logs(self):
        try:
            conn = db_connect()
            cur  = conn.cursor()
            cur.execute(
                "SELECT timestamp, ip_address, action, status FROM audit_logs ORDER BY timestamp DESC LIMIT 100"
            )
            rows = cur.fetchall()
            cur.close()
            conn.close()

            lines = []
            for row in rows:
                ts, ip, action, status = row
                t   = ts.strftime("%H:%M:%S")
                tag = {"Critical": "critical", "Alert": "alert"}.get(status, "info")
                icon = {"Critical": "🚨", "Alert": "⚠ ", "Info": "ℹ "}.get(status, "·")

                lines += [
                    (f"{icon} [{t}]  ", "timestamp"),
                    (f"{ip}\n", "dim"),
                    (f"   {action}  →  ", None),
                    (f"{status}\n\n", tag),
                ]

                # Auto-snapshot on Critical
                if row == rows[0] and status == "Critical":
                    if self._last_snap_ts != ts:
                        cap = self.master.cap
                        if cap and cap.isOpened():
                            ret, frame = cap.read()
                            if ret:
                                fname = f"{ALERTS_DIR}/ALERT_{ts.strftime('%Y-%m-%d_%H-%M-%S')}.jpg"
                                cv2.imwrite(fname, frame)
                                print(f"📸 Snapshot saved: {fname}")
                                self._last_snap_ts = ts

            self._write_log(self._sec_txt, lines if lines else [("No events recorded.\n", "dim")])

        except Exception as e:
            self._write_log(self._sec_txt, [(f"[ERROR] {e}\n", "critical")])

    def _fetch_login_logs(self):
        try:
            conn = db_connect()
            cur  = conn.cursor()
            cur.execute(
                "SELECT timestamp, username, ip_address, status, reason FROM login_logs ORDER BY timestamp DESC LIMIT 100"
            )
            rows = cur.fetchall()
            cur.close()
            conn.close()

            lines = []
            for row in rows:
                ts, uname, ip, status, reason = row
                t    = ts.strftime("%H:%M:%S")
                tag  = "success" if status == "Success" else "failed"
                icon = "✅" if status == "Success" else "❌"
                note = f" ({reason})" if reason else ""

                lines += [
                    (f"{icon} [{t}]  ", "timestamp"),
                    (f"{uname}", "bold" if status == "Success" else "failed"),
                    (f"  from {ip}\n", "dim"),
                    (f"   {status}{note}\n\n", tag),
                ]

            self._write_log(self._login_txt, lines if lines else [("No login records.\n", "dim")])

        except Exception as e:
            self._write_log(self._login_txt, [(f"[ERROR] {e}\n", "critical")])

    def _fetch_stats(self):
        try:
            conn = db_connect()
            cur  = conn.cursor()

            cur.execute("SELECT COUNT(*) FROM audit_logs WHERE status = 'Critical'")
            critical = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM audit_logs")
            total = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM login_logs")
            logins = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM login_logs WHERE status = 'Failed'")
            failed = cur.fetchone()[0]

            cur.close()
            conn.close()

            snap_count = len([f for f in os.listdir(ALERTS_DIR) if f.endswith(".jpg")])

            self._s_critical.configure(text=str(critical))
            self._s_alerts.configure(text=str(total))
            self._s_logins.configure(text=str(logins))
            self._s_failed.configure(text=str(failed))
            self._s_snapshots.configure(text=str(snap_count))

        except Exception as e:
            print(f"[STATS] {e}")

    def _logout(self):
        if self.master.cap:
            self.master.cap.release()
            self.master.cap = None
        self.master.show_login()


# ═══════════════════════════════════════════════════════════
#  MAIN APPLICATION WINDOW
# ═══════════════════════════════════════════════════════════

class NetadApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Netad – CCTV Security System")
        self.resizable(False, False)
        self.cap = None
        self.show_login()

    def show_login(self):
        self._clear()
        self.geometry("460x560")
        LoginFrame(self).pack(fill="both", expand=True)

    def show_dashboard(self, username: str, role: str = "viewer"):
        self._clear()
        self.geometry("1150x780")
        self.cap = cv2.VideoCapture(CAMERA_SRC, cv2.CAP_DSHOW if isinstance(CAMERA_SRC, int) else 0)
        DashboardFrame(self, username, role).pack(fill="both", expand=True)

    def _clear(self):
        for w in self.winfo_children():
            w.destroy()

    def on_close(self):
        if self.cap:
            self.cap.release()
        self.destroy()


# ─── ENTRY POINT ──────────────────────────────────────────
if __name__ == "__main__":
    app = NetadApp()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()
