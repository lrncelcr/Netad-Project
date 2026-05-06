import customtkinter as ctk
import psycopg2
from tkinter import messagebox

# ⚠️ PASTE YOUR RAILWAY CONNECTION URL HERE:
DB_URL = "postgresql://user:password@host.railway.app:5432/railway"

def fetch_logs():
    try:
        # Connect to Railway
        conn = psycopg2.connect(DB_URL)
        cur = conn.cursor()
        
        # Pull the latest logs
        cur.execute("SELECT timestamp, ip_address, action, status FROM audit_logs ORDER BY timestamp DESC LIMIT 5")
        rows = cur.fetchall()

        # Clear the old text
        log_textbox.delete("0.0", "end")
        
        # Display the new logs
        for row in rows:
            log_entry = f"{row[0]} | IP: {row[1]} | Action: {row[2]} | Status: {row[3]}\n"
            log_textbox.insert("end", log_entry)

        cur.close()
        conn.close()
    except Exception as e:
        messagebox.showerror("Connection Error", f"Failed to connect to DB.\nError: {e}")

# --- UI Layout ---
app = ctk.CTk()
app.title("Netad: CCTV Security")
app.geometry("700x500")

label = ctk.CTkLabel(app, text="CCTV INTRUSION DETECTION SYSTEM", font=("Roboto", 20, "bold"))
label.pack(pady=20)

# A text box to show the logs
log_textbox = ctk.CTkTextbox(app, width=600, height=300, font=("Consolas", 14))
log_textbox.pack(pady=10)

btn = ctk.CTkButton(app, text="Fetch Latest Logs", command=fetch_logs)
btn.pack(pady=10)

app.mainloop()