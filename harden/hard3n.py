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
                            Version: 1.3.7
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
    """Handles logging for both console and log file"""
    print(message)
    logging.info(message)

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

# EXECUTE SHELL COMMANDS
def exec_command(command, check=True):
    """Executes shell commands with logging and error handling."""
    try:
        result = subprocess.run(command, shell=True, check=check, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        log(f"Command executed: {command}\nOutput: {result.stdout.strip()}")
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        log(f"Command failed: {command}\nError: {e.stderr.strip()}")
        return None

# INSTALL MISSING SECURITY TOOLS
def ensure_security_tools():
    """Ensures necessary security tools are installed"""
    tools = ["ufw", "fail2ban", "clamav", "apparmor", "apparmor-utils", "bubblewrap"]
    for tool in tools:
        if shutil.which(tool) is None:
            log(f"{tool} not found. Installing...")
            exec_command(f"apt install -y {tool}")

# CONFIGURE UFW WITHOUT BREAKING INTERNET
def configure_firewall():
    """Configures UFW to block inbound while allowing outbound traffic"""
    update_status("Configuring Firewall")
    exec_command("ufw default deny incoming")
    exec_command("ufw default allow outgoing")  
    exec_command("ufw enable")
    log("Firewall configured to block inbound and allow outbound connections.")

# GET TOTAL SCAN SIZE
def get_total_scan_size(scan_dirs):
    """Calculates total disk space being scanned."""
    total_size = 0
    for directory in scan_dirs:
        try:
            output = subprocess.check_output(f"du -sb {directory} 2>/dev/null", shell=True, text=True).split()[0]
            total_size += int(output)
        except (subprocess.CalledProcessError, IndexError, ValueError):
            log(f"Skipping {directory}: Unable to calculate size.")
    
    log(f"Total disk space to scan: {total_size / (1024**3):.2f} GB")  
    status_gui.update_status(f"Total scan size: {total_size / (1024**3):.2f} GB")  
    return total_size

# RUN SECURITY AUDITS
def run_audits():
    update_status("Running Security Audits")
    exec_command("freshclam")

    scan_dirs = ["/home", "/var/log", "/etc", "/usr/bin"]
    total_scan_size = get_total_scan_size(scan_dirs)
    scanned_size = 0

    process = subprocess.Popen(
        "clamscan -r /home --infected --max-filesize=100M --max-scansize=500M --log=/var/log/clamav_scan.log",
        shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )

    for line in iter(process.stdout.readline, ''):
        if "Scanned files" in line:
            scanned_size += 100 * 1024 * 1024 
            progress_percent = min(int((scanned_size / total_scan_size) * 100), 100)
            update_status(f"Scanning: {progress_percent}% complete", progress_percent)
    
    process.wait()
    exec_command("lynis audit system --quick | tee /var/log/lynis_audit.log")
    update_status("Security audits completed.")

# START HARDENING
def start_hardening():
    ensure_security_tools()
    threading.Thread(target=lambda: [
        configure_firewall(),
        run_audits()
    ], daemon=True).start()

# MAIN
def main():
    print_ascii_art()
    status_gui.root.after(100, start_hardening)
    status_gui.run()

if __name__ == "__main__":
    main()
