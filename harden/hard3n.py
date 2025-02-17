import os
import subprocess
import shutil
import sys
import logging
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

# ASCII ART 
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

        self.label = tk.Label(self.root, text="Starting system hardening...", font=("Mono", 12), wraplength=480)
        self.label.pack(pady=20)

        self.progress = ttk.Progressbar(self.root, length=400, mode="determinate")
        self.progress.pack(pady=10)

        self.close_button = tk.Button(self.root, text="Close", command=self.root.quit, state=tk.DISABLED)
        self.close_button.pack(pady=10)

        self.total_steps = 6
        self.current_step = 0

    def update_status(self, message):
        """Updates the GUI progress"""
        self.current_step += 1
        progress_percent = int((self.current_step / self.total_steps) * 100)
        self.label.config(text=message)
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

# INITIALIZE GUI
status_gui = StatusGUI()

# STATUS COUNTER
status_step = 0
total_steps = 6

def update_status(step_name):
    """Updates both the console log and GUI"""
    global status_step
    status_step += 1
    message = f"[{status_step}/{total_steps}] {step_name}..."
    print(message)
    logging.info(message)
    status_gui.update_status(step_name)

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
        exit(1)

# SYSTEM HARDENING 
def enable_cpu_mitigations():
    update_status("Enabling CPU Mitigations")
    exec_command("cp /etc/default/grub /etc/default/grub.bak")
    exec_command(
        "sudo sed -i 's|^GRUB_CMDLINE_LINUX=\"|GRUB_CMDLINE_LINUX=\"mitigations=auto spectre_v2=on spec_store_bypass_disable=on "
        "l1tf=full,force mds=full tsx=off tsx_async_abort=full l1d_flush=on mmio_stale_data=full retbleed=auto |' /etc/default/grub"
    )
    exec_command("sudo update-grub")

def install_security_tools():
    update_status("Installing Security Tools")
    exec_command("apt update")
    exec_command("apt upgrade -y")
    exec_command("apt install -y podman firejail bubblewrap ufw fail2ban clamav lynis apparmor apparmor-utils")

def configure_firewall(ssh_needed, ssh_port=22, ssh_out_port=22):
    update_status("Configuring Firewall")
    exec_command("sudo ufw enable")
    exec_command("sudo ufw default deny incoming")
    exec_command("sudo ufw default allow outgoing")

    if ssh_needed:
        exec_command(f"sudo ufw allow {ssh_port}")
        exec_command(f"sudo ufw allow out {ssh_out_port}")


def setup_sandboxing():
    update_status("Configuring Browser Sandboxing")
    user_home = os.path.expanduser("~" + os.getenv("SUDO_USER", os.getenv("USER", "")))
    browsers = {
        "firefox": f"{user_home}/.mozilla",
        "google-chrome": f"{user_home}/.config/google-chrome"
    }
    
    for browser, profile in browsers.items():
        if shutil.which(browser):  # Checks if installed
            if os.path.exists(profile): 
                exec_command(
                    f"bwrap --ro-bind / / --dev /dev --proc /proc --unshare-all "
                    f"--bind {profile} {profile} -- {browser}"
                )
            else:
                log(f"{browser} profile directory not found at {profile}, skipping sandboxing.")
        else:
            log(f"{browser} not found, skipping sandboxing.")

def run_audits():
    update_status("Running Security Audits")
    exec_command("freshclam")
    scan_dirs = ["/home", "/var/log", "/etc", "/usr/bin"]
    for dir in scan_dirs:
        exec_command(f"clamscan -r {dir} --infected --max-filesize=100M --exclude-dir='/home/tim/Videos' --log={LOG_DIR}/clamav_scan_{DATE}.log &")
    exec_command(f"lynis audit system | tee {LOG_DIR}/lynis_audit_{DATE}.log")

# start_hardening
def start_hardening():
    """Runs the system hardening process inside the GUI event loop."""
    enable_cpu_mitigations()
    install_security_tools()
    
    ssh_needed = input("Do you need SSH access? (y/n): ").strip().lower() == "y"
    configure_firewall(ssh_needed)
    setup_sandboxing()
    run_audits()

    status_gui.complete()
    log("System hardening complete. Reboot required.")

    if input("Reboot now? (y/n): ").strip().lower() == "y":
        exec_command("sudo reboot")

# MAIN 
def main():
    print_ascii_art()  
    status_gui.root.after(100, start_hardening)  
    status_gui.run()

if __name__ == "__main__":
    main()
