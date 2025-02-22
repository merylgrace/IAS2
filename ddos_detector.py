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
