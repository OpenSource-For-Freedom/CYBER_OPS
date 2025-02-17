import os
import subprocess
import shutil
import sys
import signal
import time
import logging
import threading
import tkinter as tk
from tkinter import ttk  
from datetime import datetime
from hard3n_tk import Hard3nGUI  

# Ensure root
def ensure_root():
    if os.geteuid() != 0:
        print("Restarting as root...")
        try:
            subprocess.run(["sudo", sys.executable] + sys.argv, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Failed to elevate to root: {e}")
        sys.exit(0)

ensure_root()

# Print ASCII banner
def print_ascii_art():
    art = """
    --------------------------------------------------------------------------
                H|   H|  AAAAA    RRRR    DDDD    333333    NN     N|
      ======== H|   H|  A    A   R   R   D   D       33    N N    N| ========
      ======= HHHHH    AAAAAA   RRRR    D   D     33      N|  N  N| =========
      ====== H|   H|  A    A   R  R    D   D       33    N|   N N| ==========
            H|   H|  A    A   R   R   DDDD    333333    N|    NN|
    --------------------------------------------------------------------------
                "HARD3N" - The Linux Security Project
                ----------------------------------------
                 A project focused on improving Linux
                security by automating, containerizing
                            Hardening and
                     System protection measures.
                         License: MIT License
                            Version: 1.3.2
                           Dev: Tim "TANK" Burns
      GitHub: https://github.com/OpenSource-For-Freedom/Linux.git
    """
    print(art)

# STATUS GUI 
class StatusGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("HARD3N - System Hardening Progress")
        self.root.geometry("500x300")
        self.root.resizable(False, False)

        self.label = tk.Label(self.root, text="Starting system hardening...", font=("Mono", 14), wraplength=480)
        self.label.pack(pady=20)

        self.progress = ttk.Progressbar(self.root, length=400, mode="determinate")  
        self.progress.pack(pady=10)

        self.close_button = tk.Button(self.root, text="Close", command=self.root.quit, state=tk.DISABLED)
        self.close_button.pack(pady=10)

        self.total_steps = 8
        self.current_step = 0

    def update_status(self, message, progress=None):
        """Updates the GUI progress"""
        self.label.config(text=message)
        if progress is not None:
            self.progress["value"] = progress
        else:
            self.current_step += 1
            progress_percent = int((self.current_step / self.total_steps) * 100)
            self.progress["value"] = progress_percent
        self.root.update_idletasks()

    def complete(self):
        """Marks completion of process"""
        self.label.config(text="System Hardening Complete!")
        self.progress["value"] = 100
        self.close_button.config(state=tk.NORMAL)
        self.root.update_idletasks()

    def run(self):
        """Runs the GUI"""
        self.root.mainloop()

status_gui = StatusGUI()

# CONFIGURE LOGGING
LOG_DIR = os.path.expanduser("~/security_logs")
os.makedirs(LOG_DIR, exist_ok=True)
DATE = datetime.now().strftime("%Y%m%d_%H%M%S")
SCRIPT_LOG = os.path.join(LOG_DIR, f"script_execution_{DATE}.log")

logging.basicConfig(
    filename=SCRIPT_LOG,
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def log(message):
    print(message)
    logging.info(message)

def exec_command(command, check=True):
    try:
        subprocess.run(command, shell=True, check=check, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        log(f"Command failed: {command} | Error: {e.stderr}")

# CLEAN EXIT
def cleanup_and_exit(signal_received=None, frame=None):
    """Handles clean exit when CTRL+C is pressed."""
    log("CTRL+C detected. Cleaning up and exiting...")
    subprocess.run("pkill clamscan", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run("pkill lynis", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if status_gui.root.winfo_exists():
        status_gui.root.quit()
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup_and_exit)

# SYSTEM HARDENING
def enable_cpu_mitigations():
    status_gui.update_status("Enabling CPU Mitigations")
    exec_command("cp /etc/default/grub /etc/default/grub.bak")
    exec_command("update-grub")

def setup_sandboxing():
    status_gui.update_status("Configuring Browser Sandboxing")
    exec_command("apt install -y firejail bubblewrap")

def run_audits():
    status_gui.update_status("Running Security Audits")
    exec_command("freshclam")

    process = subprocess.Popen(
        "clamscan -r /home --infected --max-filesize=100M --max-scansize=500M --log=/var/log/clamav_scan.log",
        shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )

    for line in iter(process.stdout.readline, ''):
        if "Scanned files" in line:
            status_gui.update_status(f"Scanning: {line.strip()}")
    
    process.wait()
    exec_command("lynis audit system --quick | tee /var/log/lynis_audit.log")
    status_gui.update_status("Security audits completed.")

# NEW SECURITY TASKS
def enable_unattended_upgrades():
    status_gui.update_status("Enabling Unattended Security Updates")
    exec_command("apt install -y unattended-upgrades")
    exec_command("dpkg-reconfigure -plow unattended-upgrades")

def setup_security_cron_jobs():
    status_gui.update_status("Setting up security automation")
    cron_jobs = [
        "@daily apt update && apt upgrade -y",
        "@weekly lynis audit system >> /var/log/lynis_weekly.log"
    ]
    for job in cron_jobs:
        exec_command(f"(crontab -l 2>/dev/null; echo \"{job}\") | crontab -")

# START IT UP
def start_hardening():
    threading.Thread(target=lambda: [
        enable_cpu_mitigations(),
        setup_sandboxing(),
        run_audits(),
        enable_unattended_upgrades(),
        setup_security_cron_jobs()
    ], daemon=True).start()

# MAIN
def main():
    print_ascii_art()
    status_gui.root.after(100, start_hardening)
    status_gui.run()

if __name__ == "__main__":
    main()