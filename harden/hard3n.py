import os
import subprocess
import shutil
import sys
import signal
import time
import logging
import threading
from datetime import datetime
import tkinter as tk
from tkinter import ttk  
from hard3n_tk import Hard3nGUI  

# RUNS AS ROOT
def ensure_root():
    if os.geteuid() != 0:
        print("Restarting as root...")
        try:
            subprocess.run(["sudo", sys.executable] + sys.argv, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Failed to elevate to root: {e}")
        sys.exit(0)

ensure_root()

# Print the ASCII art and text
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

        self.total_steps = 6
        self.current_step = 0

    def update_status(self, message):
        """Updates the GUI progress"""
        self.label.config(text=message)
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

# STATUS COUNTER
def update_status(step_name):
    """Updates both the console log and GUI"""
    message = f"{step_name}..."
    print(message)
    logging.info(message)
    status_gui.update_status(step_name)
def cleanup_and_exit(signal_received=None, frame=None):
    """Handles clean exit when CTRL+C is pressed."""
    log("CTRL+C detected. Cleaning up and exiting...")
    
    # kill process smoothly
    subprocess.run("pkill clamscan", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run("pkill lynis", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
   # quit gui via root
    if status_gui.root.winfo_exists():
        status_gui.root.quit()

    sys.exit(0)

# SYSTEM HARDENING
def setup_sandboxing():
    update_status("Configuring Browser Sandboxing")
    user_home = os.path.expanduser("~" + os.getenv("SUDO_USER", os.getenv("USER", "")))

    browser_map = {
        "firefox": (f"{user_home}/.mozilla", "/usr/bin/firefox"),
        "google-chrome": (f"{user_home}/.config/google-chrome", "/usr/bin/google-chrome"),
    }

    for browser, (profile_dir, binary_path) in browser_map.items():
        if shutil.which(browser):
            log(f"Configuring Bubblewrap sandbox for {browser}...")
            if os.path.exists(profile_dir):  
                exec_command(
                    f"bwrap --ro-bind / / --dev /dev --proc /proc --unshare-all "
                    f"--bind {profile_dir} {profile_dir} -- {browser}"
                )
            else:
                log(f"{browser} profile directory not found at {profile_dir}, skipping sandboxing.")
        else:
            log(f"{browser} not found, skipping sandboxing.")
            
# Handle CTRL+C for clean exit
signal.signal(signal.SIGINT, cleanup_and_exit)

def get_total_scan_size(scan_dirs):
    """Calculates the total disk space used by the directories being scanned."""
    total_size = 0
    for directory in scan_dirs:
        try:
            output = subprocess.check_output(f"du -sb {directory} 2>/dev/null", shell=True, text=True).split()[0]
            total_size += int(output)
        except (subprocess.CalledProcessError, IndexError, ValueError):
            log(f"Skipping {directory}: Unable to calculate size.")
    return total_size


# run audits
def run_audits():
    update_status("Running Security Audits")
    log("Updating ClamAV database...")
    exec_command("freshclam")

    scan_dirs = ["/home", "/var/log", "/etc", "/usr/bin"]
    total_scan_size = get_total_scan_size(scan_dirs)  # Get total size in bytes***
    scanned_size = 0

    log(f"Total disk space to scan: {total_scan_size / (1024**3):.2f} GB")
    log("Starting ClamAV scan...")

    try:
        for index, directory in enumerate(scan_dirs, start=1):
            update_status(f"Scanning {directory} ({index}/{len(scan_dirs)})")

            process = subprocess.Popen(
                f"clamscan -r {directory} --infected --max-filesize=100M --max-scansize=500M "
                f"--exclude-dir='/home/tim/Videos' --exclude-dir='/home/tim/Downloads' --exclude-dir='/var/cache' "
                f"--log={LOG_DIR}/clamav_scan_{DATE}.log",
                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )

            for line in iter(process.stdout.readline, ''):
                if "Scanned files" in line:
                    scanned_size += 100 * 1024 * 1024  # Estimate of space
                    progress_percent = min(int((scanned_size / total_scan_size) * 100), 100)
                    update_status(f"Scanning {directory} - {progress_percent}% complete")
                    status_gui.progress["value"] = progress_percent
                    status_gui.root.update()

                elif "FOUND" in line:
                    log(f"Infected file found: {line.strip()}")

            process.wait()

            log(f"Completed scan for {directory}")

        log("Running Lynis system audit...")
        exec_command(f"lynis audit system --quick | tee {LOG_DIR}/lynis_audit_{DATE}.log")

        update_status("Security audits completed.")
        log("Security audits completed. Check logs for details.")

    except KeyboardInterrupt:
        cleanup_and_exit()
# set gid perms
def track_setgid_permissions():
    """Finds all files with setgid permissions and logs them."""
    update_status("Tracking setgid permissions")
    log("Tracking files with setgid permissions...")

    try:
        exec_command(
            "find / -mount -perm -2000 -type f -exec ls -ld {} \; > /home/user/setgid_.txt && chown user:user /home/user/setgid_.txt"
        )
        log("Setgid permission report saved to /home/user/setgid_.txt")
    except Exception as e:
        log(f"Error tracking setgid files: {e}")

# THREADING FOR AUDITS
def start_hardening():
    """Runs the system hardening process inside the GUI event loop."""
    hardening_thread = threading.Thread(target=lambda: [
        enable_cpu_mitigations(),
        install_security_tools(),
        track_setgid_permissions(),
        enforce_password_expiration(),
        harden_network(),
        enable_unattended_upgrades(),
        setup_security_cron_jobs(),
        run_audits()
    ], daemon=True)
    hardening_thread.start()

    
# PASSWORD STUFF
    def enforce_password_expiration():
    """Sets a password expiration policy for all users."""
    update_status("Enforcing password policy")
    log("Setting expiration policies for all users...")

    try:
        exec_command("sudo chage -M 90 -m 7 -W 14 $(whoami)")
        log("Password expiration policy applied: max 90 days, min 7 days, warning 14 days before expiration.")
    except Exception as e:
        log(f"Error setting password expiration policy: {e}")

# NETWORK STUFF
def harden_network():
    """Applies network security configurations from the README."""
    update_status("Applying network hardening")
    log("Applying recommended sysctl.conf security settings...")

    try:
        exec_command(
            "echo '\n"
            "net.ipv4.conf.all.rp_filter = 1\n"
            "net.ipv4.tcp_syncookies = 1\n"
            "net.ipv4.icmp_echo_ignore_broadcasts = 1\n"
            "net.ipv6.conf.all.accept_source_route = 0\n"
            "net.ipv6.conf.all.accept_redirects = 0\n"
            "' | sudo tee -a /etc/sysctl.conf"
        )
        exec_command("sudo sysctl -p")  # Apply changes asap
        log("Network security parameters applied.")
    except Exception as e:
        log(f"Error hardening network parameters: {e}")

# UPGRADE STUFF
def enable_unattended_upgrades():
    """Installs and configures unattended-upgrades."""
    update_status("Enabling automatic security updates")
    log("Installing and enabling unattended-upgrades...")

    try:
        exec_command("sudo apt install -y unattended-upgrades")
        exec_command(
            "echo 'APT::Periodic::Update-Package-Lists \"1\";\n"
            "APT::Periodic::Unattended-Upgrade \"1\";' | sudo tee /etc/apt/apt.conf.d/20auto-upgrades"
        )
        exec_command("sudo dpkg-reconfigure -plow unattended-upgrades")
        log("Unattended security updates enabled.")
    except Exception as e:
        log(f"Error enabling automatic updates: {e}")

# CRON UPDATES AND LOG CHECKS
def setup_security_cron_jobs():
    """Creates cron jobs for periodic security tasks."""
    update_status("Setting up security automation")
    log("Adding security-related cron jobs...")

    try:
        cron_jobs = [
            "@daily sudo apt update && sudo apt upgrade -y",
            "@weekly sudo lynis audit system >> /var/log/lynis_weekly.log",
            "@weekly sudo find / -perm -2000 -type f -exec ls -ld {} \; > /home/user/setgid_.txt",
        ]

        for job in cron_jobs:
            exec_command(f"(crontab -l 2>/dev/null; echo \"{job}\") | crontab -")

        log("Security cron jobs added successfully.")
    except Exception as e:
        log(f"Error adding cron jobs: {e}")


# MAIN
def main():
    print_ascii_art()  
    status_gui.root.after(100, start_hardening)  
    status_gui.run()  # Start GUI 

if __name__ == "__main__":
    main()
