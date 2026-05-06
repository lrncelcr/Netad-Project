import customtkinter as ctk
import psycopg2
import cv2
from PIL import Image, ImageTk
from datetime import datetime

import os
from dotenv import load_dotenv

# Load the variables from the .env file
load_dotenv()

# Get the URL from the environment
DB_URL = os.getenv("DATABASE_URL")

# --- DATABASE LOGIC ---
def fetch_logs():
    try:
        conn = psycopg2.connect(DB_URL)
        cur = conn.cursor()
        cur.execute("SELECT timestamp, ip_address, action, status FROM audit_logs ORDER BY timestamp DESC LIMIT 8")
        rows = cur.fetchall()

        log_textbox.delete("0.0", "end")
        for row in rows:
            # Formatting the time for a cleaner look
            time_str = row[0].strftime('%H:%M:%S')
            log_entry = f"[{time_str}] IP: {row[1]} | {row[2]} | {row[3]}\n"
            log_textbox.insert("end", log_entry)
        
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Sync Error: {e}")

# --- CAMERA LOGIC ---
def update_frame():
    ret, frame = cap.read()
    if ret:
        # Convert BGR to RGB and resize for the UI
        cv_img = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        img = Image.fromarray(cv_img)
        img = img.resize((620, 320)) 
        imgtk = ImageTk.PhotoImage(image=img)
        video_label.imgtk = imgtk
        video_label.configure(image=imgtk)
    
    video_label.after(15, update_frame) # Smooth 60fps-ish feel

# --- AUTO-REFRESH LOGIC ---
def auto_refresh():
    fetch_logs()
    app.after(5000, auto_refresh) # Refresh logs every 5 seconds

# --- UI SETUP (Quiet Luxury Aesthetic) ---
app = ctk.CTk()
app.title("Netad: CCTV Security System")
app.geometry("850x750")
ctk.set_appearance_mode("dark")

# Header
header = ctk.CTkLabel(app, text="SECURE FEED : LIVE MONITORING", font=("Inter", 22, "bold"), text_color="#FFFFFF")
header.pack(pady=(20, 10))

# Video Display (The "CCTV Screen")
video_label = ctk.CTkLabel(app, text="", fg_color="#121212", corner_radius=8)
video_label.pack(pady=10)

# Log Section
log_label = ctk.CTkLabel(app, text="SECURITY AUDIT LOGS", font=("Inter", 12, "bold"), text_color="#888888")
log_label.pack(pady=(10, 0))

log_textbox = ctk.CTkTextbox(app, width=700, height=200, font=("Consolas", 12), 
                             fg_color="#181818", border_color="#2A2A2A", border_width=1)
log_textbox.pack(pady=10)

# Initialize Camera and Loops
cap = cv2.VideoCapture(0) 
update_frame()
auto_refresh()

app.mainloop()
cap.release()