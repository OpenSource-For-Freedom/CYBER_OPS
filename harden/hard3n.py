# its haning up on security audits, going to let it run and see where it goes. 

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

# ROOT ENSURE
def ensure_root():
    if os.geteuid() != 0:
        print("Restarting as root...")
        try:
            subprocess.run(["sudo", sys.executable] + sys.argv, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Failed to elevate to root: {e}")
        sys.exit(0)

ensure_root()

# PRINT BANNER
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
                            Version: 1.4.2
                           Dev: Tim "TANK" Burns
      GitHub: https://github.com/OpenSource-For-Freedom/Linux.git
    """
    print(art)

# LOGGING SETUP
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

# EXECUTE COMMAND SAFELY
def exec_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        log(f"Command executed: {command}\nOutput: {result.stdout.strip()}")
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        log(f"Command failed: {command}\nError: {e.stderr.strip()}")
        return None

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

        self.total_steps = 12
        self.current_step = 0

    def update_status(self, message, progress=None):
        self.label.config(text=message)
        if progress is not None:
            self.progress["value"] = progress
        else:
            self.current_step += 1
            progress_percent = int((self.current_step / self.total_steps) * 100)
            self.progress["value"] = progress_percent
        self.root.update_idletasks()

    def complete(self):
        self.label.config(text="System Hardening Complete!")
        self.progress["value"] = 100
        self.close_button.config(state=tk.NORMAL)
        self.root.update_idletasks()

    def run(self):
        self.root.mainloop()

status_gui = StatusGUI()

# INSTALL SECURITY TOOLS IF MISSING
def ensure_security_tools():
    tools = ["ufw", "fail2ban", "clamav", "apparmor", "apparmor-utils", "bubblewrap"]
    for tool in tools:
        if shutil.which(tool) is None:
            log(f"{tool} not found. Installing...")
            status_gui.update_status(f"Installing {tool}...")
            exec_command(f"DEBIAN_FRONTEND=noninteractive apt install -y {tool}")

# SYSTEM HARDENING FUNCTIONS
def configure_firewall():
    status_gui.update_status("Configuring Firewall")
    exec_command("ufw default deny incoming")
    exec_command("ufw default allow outgoing")
    exec_command("ufw --force enable")  # Prevents user confirmation freeze

def enforce_password_policies():
    status_gui.update_status("Enforcing Password Policies")
    exec_command("chage -M 90 -m 7 -W 14 $(whoami)")

def track_setgid_permissions():
    status_gui.update_status("Tracking SetGID Permissions")
    home_path = os.path.expanduser("~")
    setgid_log = os.path.join(home_path, "setgid_permissions.txt")
    exec_command(f"find / -mount -perm -2000 -type f -exec ls -ld {{}} \\; > {setgid_log}")
    exec_command(f"chown $(whoami):$(whoami) {setgid_log}")

def enable_auto_updates():
    status_gui.update_status("Enabling Automatic Security Updates")
    exec_command("apt install -y unattended-upgrades")
    exec_command("dpkg-reconfigure -plow unattended-upgrades")

def setup_security_cron_jobs():
    status_gui.update_status("Setting up security automation")
    cron_jobs = [
        "@daily apt update && apt upgrade -y",
        "@weekly lynis audit system >> /var/log/lynis_weekly.log",
        "@weekly find / -perm -2000 -type f -exec ls -ld {} \\; > ~/setgid_permissions.txt"
    ]
    for job in cron_jobs:
        exec_command(f"(crontab -l 2>/dev/null; echo \"{job}\") | crontab -")

def run_audits():
    status_gui.update_status("Running Security Audits")
    exec_command("freshclam")
    exec_command("clamscan -r /home --infected --log=/var/log/clamav_scan.log &")  # Runs in background
    exec_command("lynis audit system --quick | tee /var/log/lynis_audit.log")

# MAIN FUNCTION
def start_hardening():
    ensure_security_tools()
    threading.Thread(target=lambda: [
        configure_firewall(),
        enforce_password_policies(),
        track_setgid_permissions(),
        enable_auto_updates(),
        setup_security_cron_jobs(),
        run_audits()
    ], daemon=True).start()

def main():
    print_ascii_art()
    status_gui.root.after(100, start_hardening)
    status_gui.run()

if __name__ == "__main__":
    main()
