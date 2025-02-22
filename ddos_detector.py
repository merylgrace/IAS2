import tkinter as tk
from tkinter import messagebox, scrolledtext
import psutil
import subprocess
import threading
import time

#detection
THRESHOLD = 1000000  # 1 Mbps
SCAN_INTERVAL = 5  # Monitor traffic every 5 seconds
BLOCKLIST = set()  # Stores blocked IPs

#monitor the network traffic
def monitor_traffic():
    while True:
        net_io = psutil.net_io_counters()
        sent_bytes = net_io.bytes_sent
        recv_bytes = net_io.bytes_recv

        time.sleep(SCAN_INTERVAL)

        new_net_io = psutil.net_io_counters()
        new_sent_bytes = new_net_io.bytes_sent
        new_recv_bytes = new_net_io.bytes_recv

        upload_speed = (new_sent_bytes - sent_bytes) / SCAN_INTERVAL
        download_speed = (new_recv_bytes - recv_bytes) / SCAN_INTERVAL
        total_speed = upload_speed + download_speed

        status_label.config(text=f"Upload: {upload_speed/1024:.2f} KB/s | Download: {download_speed/1024:.2f} KB/s")
        log_message(f"Traffic: {total_speed/1024:.2f} KB/s")

        if total_speed > THRESHOLD:
            detect_attack(total_speed)

#detects and prevents the ddos attack
def detect_attack(speed):
    log_message(f"DDoS Detected! Traffic: {speed/1024:.2f} KB/s")
    messagebox.showwarning("Warning!", f"Possible DDoS attack detected! Traffic: {speed/1024:.2f} KB/s")

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

#to block the attacker's IP
def block_ip(ip):
    try:
        cmd = f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}'
        subprocess.run(cmd, shell=True, check=True)
        log_message(f"Blocked IP: {ip}")
        messagebox.showinfo("Blocked!", f"Attacker IP {ip} has been blocked!")
    except Exception as e:
        log_message(f"Error blocking IP: {e}")
        messagebox.showerror("Error", f"Failed to block IP: {e}")

#logging messages
def log_message(message):
    log_text.insert(tk.END, f"{message}\n")
    log_text.see(tk.END)

#GUI
root = tk.Tk()
root.title("DDoS Detection & Prevention")
root.geometry("500x300")
root.configure(bg="black")

#GUI elements
title_label = tk.Label(root, text="DDoS Detection System", font=("Arial", 14, "bold"), fg="white", bg="black")
title_label.pack(pady=10)

status_label = tk.Label(root, text="Monitoring...", font=("Arial", 12), fg="lime", bg="black")
status_label.pack()

#log box for alerts
log_text = scrolledtext.ScrolledText(root, width=60, height=10, bg="black", fg="white", font=("Arial", 10))
log_text.pack(pady=5)

#start and exit buttons
start_button = tk.Button(root, text="Start Monitoring", command=lambda: threading.Thread(target=monitor_traffic, daemon=True).start(), font=("Arial", 12), bg="green", fg="white")
start_button.pack(pady=5)

exit_button = tk.Button(root, text="Exit", command=root.quit, font=("Arial", 12), bg="red", fg="white")
exit_button.pack(pady=5)

#to run the GUI
root.mainloop()