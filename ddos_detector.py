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
