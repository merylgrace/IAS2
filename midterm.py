import tkinter as tk
from tkinter import messagebox, scrolledtext
import psutil
import subprocess
import threading
import time
import re
from supabase import create_client, Client

# Supabase config
SUPABASE_URL = "https://nlqpsslgztazeznlckvh.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5scXBzc2xnenRhemV6bmxja3ZoIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDMyMzc5ODEsImV4cCI6MjA1ODgxMzk4MX0.wGnRb8yEV7sliHFh03ozt9_fSo4xYQ0rUapSL0p0dVg"
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Threshold and interval for monitoring
THRESHOLD = 300000  # 300 KB/s
SCAN_INTERVAL = 5  # in seconds
BLOCKLIST = set()

# Send Magic Link and tell user to paste token
def send_magic_link(email):
    try:
        supabase.auth.sign_in_with_otp({"email": email})
        messagebox.showinfo(
            "Magic Link Sent",
            "Magic link sent to your Gmail.\n\nClick the link, then copy the `access_token` from the browser URL and paste it in the next step."
        )
    except Exception as e:
        messagebox.showerror("Error", f"Failed to send magic link: {e}")

# After user clicks the link and pastes token
def verify_token_and_login(login_window):
    def submit_token():
        token = token_entry.get().strip()

        # Check for invalid characters
        if not token or "\n" in token or "\r" in token:
            messagebox.showerror("Invalid Token", "The token contains invalid characters. Please paste a valid access token.")
            return

        try:
            session = supabase.auth.set_session(access_token=token, refresh_token="")
            if session.user:
                login_window.destroy()
                launch_main_app()
            else:
                messagebox.showerror("Login Failed", "Invalid token or session could not be created.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start session: {e}")

    tk.Label(login_window, text="Paste access_token here:").pack(pady=5)
    token_entry = tk.Entry(login_window, width=50)
    token_entry.pack(pady=5)
    tk.Button(login_window, text="Login with Token", command=submit_token).pack(pady=10)

# Show Login Window
def show_login_window():
    login_window = tk.Tk()
    login_window.title("Login/Register with Magic Link")
    login_window.geometry("450x250")

    tk.Label(login_window, text="Enter your Gmail:").pack(pady=10)
    email_entry = tk.Entry(login_window, width=50)
    email_entry.pack()

    def handle_login():
        email = email_entry.get().strip()
        if not email:
            messagebox.showwarning("Input Error", "Email is required!")
            return
        if not re.match(r"^[a-zA-Z0-9._%+-]+@gmail\.com$", email):
            messagebox.showwarning("Invalid Email", "Only @gmail.com emails are allowed!")
            return

        send_magic_link(email)
        verify_token_and_login(login_window)

    tk.Button(login_window, text="Send Magic Link", command=handle_login).pack(pady=20)
    login_window.mainloop()

# Main Application Window
def launch_main_app():
    root = tk.Tk()
    root.title("DDoS Detection & Prevention")
    root.geometry("500x420")
    root.configure(bg="black")

    title_label = tk.Label(root, text="DDoS Detection System", font=("Arial", 14, "bold"), fg="white", bg="black")
    title_label.pack(pady=10)

    status_label = tk.Label(root, text="Press Start Monitoring", font=("Arial", 12), fg="lime", bg="black")
    status_label.pack()

    log_text = scrolledtext.ScrolledText(root, width=60, height=10, bg="black", fg="white", font=("Arial", 10))
    log_text.pack(pady=5)

    def log_message(message):
        log_text.insert(tk.END, f"{message}\n")
        log_text.see(tk.END)

    def block_ip(ip):
        try:
            cmd = f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}'
            subprocess.run(cmd, shell=True, check=True)
            log_message(f"Blocked IP: {ip}")
            messagebox.showinfo("Blocked!", f"Attacker IP {ip} has been blocked!")
        except Exception as e:
            log_message(f"Error blocking IP: {e}")
            messagebox.showerror("Error", f"Failed to block IP: {e}")

    def detect_attack(speed):
        log_message(f"DDoS Detected! Traffic: {speed/1024:.2f} KB/s")
        messagebox.showwarning("Warning!", f"Possible DDoS attack detected!\nTraffic: {speed/1024:.2f} KB/s")

        connections = psutil.net_connections(kind='inet')
        attacker_ip = None

        for conn in connections:
            if conn.raddr and conn.status == 'ESTABLISHED':
                ip = conn.raddr.ip
                if ip not in BLOCKLIST:
                    attacker_ip = ip
                    break

        if attacker_ip:
            BLOCKLIST.add(attacker_ip)
            block_ip(attacker_ip)

    def monitor_traffic():
        while True:
            net_io = psutil.net_io_counters()
            sent_bytes = net_io.bytes_sent
            recv_bytes = net_io.bytes_recv

            time.sleep(SCAN_INTERVAL)

            new_net_io = psutil.net_io_counters()
            upload_speed = (new_net_io.bytes_sent - sent_bytes) / SCAN_INTERVAL
            download_speed = (new_net_io.bytes_recv - recv_bytes) / SCAN_INTERVAL
            total_speed = upload_speed + download_speed

            status_label.config(text=f"Upload: {upload_speed/1024:.2f} KB/s | Download: {download_speed/1024:.2f} KB/s")
            log_message(f"Traffic: {total_speed/1024:.2f} KB/s")

            if total_speed > THRESHOLD:
                detect_attack(total_speed)

    def logout():
        supabase.auth.sign_out()
        messagebox.showinfo("Logged Out", "You have been logged out.")
        root.destroy()
        show_login_window()

    tk.Button(root, text="Start Monitoring", command=lambda: threading.Thread(target=monitor_traffic, daemon=True).start(),
              font=("Arial", 12), bg="green", fg="white").pack(pady=5)

    tk.Button(root, text="Logout", command=logout, font=("Arial", 12), bg="orange", fg="black").pack(pady=5)
    tk.Button(root, text="Exit", command=root.quit, font=("Arial", 12), bg="red", fg="white").pack(pady=5)

    root.mainloop()

# Start the program
show_login_window()