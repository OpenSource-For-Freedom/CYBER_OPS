import os
import subprocess
import shutil
import sys
import signal
import threading
import shlex

# EXIT
def clean_exit(signum=None, frame=None):
    """Gracefully exit the script, stopping background processes and closing the GUI."""
    status_gui.update_status("Cleaning up and exiting...")
    logging.info("HARDN exiting cleanly...")

    # Stop any background processes (modify as needed)
    try:
        subprocess.run("pkill -f clamav", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run("pkill -f freshclam", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run("pkill -f lynis", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        logging.error(f"Error stopping processes: {e}")

    # Close the GUI properly
    status_gui.root.quit()
    sys.exit(0)  # Exit script properly

import time
import logging
import threading
import getpass
import tkinter as tk
from tkinter import ttk  
from datetime import datetime
# from hardn_tk import HardnGUI  

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
             ██░ ██  ▄▄▄       ██▀███  ▓█████▄  ███▄    █ 
            ▓██░ ██▒▒████▄    ▓██ ▒ ██▒▒██▀ ██▌ ██ ▀█   █ 
            ▒██▀▀██░▒██  ▀█▄  ▓██ ░▄█ ▒░██   █▌▓██  ▀█ ██▒
            ░▓█ ░██ ░██▄▄▄▄██ ▒██▀▀█▄  ░▓█▄   ▌▓██▒  ▐▌██▒
            ░▓█▒░██▓ ▓█   ▓██▒░██▓ ▒██▒░▒████▓ ▒██░   ▓██░
             ▒ ░░▒░▒ ▒▒   ▓▒█░░ ▒▓ ░▒▓░ ▒▒▓  ▒ ░ ▒░   ▒ ▒ 
             ▒ ░▒░ ░  ▒   ▒▒ ░  ░▒ ░ ▒░ ░ ▒  ▒ ░ ░░   ░ ▒░
             ░  ░░ ░  ░   ▒     ░░   ░  ░ ░  ░    ░   ░ ░ 
             ░  ░  ░      ░  ░   ░        ░             ░ 
                                ░                 
                "HARDN" - The Linux Security Project
                ----------------------------------------
                 A project focused on improving Linux
                security by automating, containerizing
                            Hardening and
                     System protection measures.
                         License: MIT License
                            Version: 1.4.5
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

# STATUS GUI 
class StatusGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("HARDN - System Hardening Progress")
        self.root.geometry("600x400")
        self.root.resizable(False, False)

        self.label = tk.Label(self.root, text="Starting system hardening...", font=("Mono", 12), wraplength=580)
        self.label.pack(pady=10)

        self.progress = ttk.Progressbar(self.root, length=500, mode="determinate")  
        self.progress.pack(pady=10)

        self.text_area = tk.Text(self.root, height=15, width=70, state=tk.DISABLED)
        self.text_area.pack(pady=10)

        self.close_button = tk.Button(self.root, text="Close", command=clean_exit, state=tk.DISABLED)
        self.close_button.pack(pady=10)

        self.total_steps = 12
        self.current_step = 0

    def update_status(self, message, progress=None):
        self.label.config(text=message)
        self.text_area.config(state=tk.NORMAL)
        self.text_area.insert(tk.END, message + "\n")
        self.text_area.config(state=tk.DISABLED)
        self.text_area.yview(tk.END)

        if progress is not None:
            self.progress["value"] = progress
        else:
            self.current_step += 1
            progress_percent = int((self.current_step / self.total_steps) * 100)
            self.progress["value"] = progress_percent

        self.root.update_idletasks()

    def complete(self):
        self.update_status("System Hardening Complete!", 100)
        self.close_button.config(state=tk.NORMAL)

    def run(self):
        self.root.mainloop()

status_gui = StatusGUI()

# EXECUTE COMMAND & LOG IN GUI
def exec_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.strip()
        status_gui.update_status(f"{command}\n{output}\n")
        return output
    except subprocess.CalledProcessError as e:
        status_gui.update_status(f"{command}\nError: {e.stderr.strip()}\n")
        return None

# SYSTEM HARDENING... THIS IS THE HAIL MARY
def configure_firewall():
    status_gui.update_status("Configuring Firewall...")
    exec_command("ufw default deny incoming")
    username = getpass.getuser()
    exec_command(f"chage -M 90 -m 7 -W 14 {username}")
    
def configure_kernel_security():
    """Configures GRUB for kernel hardening and CPU mitigations."""
    status_gui.update_status("Configuring Kernel Security Settings...")

    # BACKUP EXIST
    backup_file = "/etc/default/grub.bak"
    if not os.path.exists(backup_file):
        exec_command("cp /etc/default/grub /etc/default/grub.bak")

    # GRUB 
    grub_config = """
    GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT lsm=apparmor,landlock,lockdown,yama,integrity,bpf apparmor=1 security=apparmor"
    GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX mitigations=auto spectre_v2=on spec_store_bypass_disable=on"
    GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX l1tf=full,force mds=full tsx=off tsx_async_abort=full"
    GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX kvm.nx_huge_pages=force l1d_flush=on mmio_stale_data=full retbleed=auto"
    GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX intel_iommu=on amd_iommu=force_isolation efi=disable_early_pci_dma"
    GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX iommu=force iommu.passthrough=0 iommu.strict=1"
    GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX kvm-intel.vmentry_l1d_flush=always random.trust_bootloader=off"
    GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX slab_nomerge page_alloc.shuffle=1 randomize_kstack_offset=on debugfs=off"
    GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX init_on_alloc=1 init_on_free=1 pti=on vsyscall=none"
    GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX loglevel=0 acpi_no_watchdog nohz_full=all nohibernate ssbd=force-on"
    GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX topology=on thermal.off=1 noearly ioapicreroute pcie_bus_perf"
    GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX rcu_nocb_poll mce=off nohpet idle=poll numa=noacpi gather_data_sampling=force"
    GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX net.ifnames=0 ipv6.disable=1 hibernate=no"
    """

    # WRITE NEW GRUB
    with open("/etc/default/grub", "a") as grub_file:
        grub_file.write(grub_config)

    # UPDATE GRUB TO APPLY
    exec_command("update-grub")
    status_gui.update_status("Kernel Security Configurations Applied. A Reboot is Required.")

# SSH BRUTE FORCE BLOCKING: FAIL2BAN
def configure_fail2ban():
    """Configures Fail2Ban to protect against brute-force attacks."""
    status_gui.update_status("Configuring Fail2Ban...")

    # Install Fail2Ban if missing
    fail2ban_installed = exec_command("dpkg -l | grep fail2ban")
    if not fail2ban_installed:
        status_gui.update_status("Fail2Ban not found. Installing now...")
        exec_command("apt install -y fail2ban")

    # Create jail.local file for monitoring 
    fail2ban_config = """
    [DEFAULT]
    bantime = 1h
    findtime = 10m
    maxretry = 3
    destemail = root@localhost
    sender = fail2ban@localhost
    action = %(action_mwl)s

    [sshd]
    enabled = true
    port = ssh
    filter = sshd
    logpath = /var/log/auth.log
    maxretry = 3
    bantime = 2h
    """

    with open("/etc/fail2ban/jail.local", "w") as jail_file:
        jail_file.write(fail2ban_config)

    # Restart Fail2Ban*
    exec_command("systemctl restart fail2ban")
    exec_command("systemctl enable fail2ban")

    status_gui.update_status("Fail2Ban Configured and Running!")
def enforce_password_policies():
    status_gui.update_status("Enforcing Password Policies...")
    exec_command("chage -M 90 -m 7 -W 14 $(whoami)")

def track_setgid_permissions():
    status_gui.update_status("Tracking SetGID Permissions...")
    exec_command("find / -mount -perm -2000 -type f -exec ls -ld {} \\; > /root/setgid_permissions.txt")
    exec_command("chown $(username):$(username) /root/setgid_permissions.txt")

def enable_auto_updates():
    status_gui.update_status("Enabling Automatic Security Updates...")
    exec_command("apt install -y unattended-upgrades")
    exec_command('echo "unattended-upgrades unattended-upgrades/enable_auto_updates boolean true" | sudo debconf-set-selections')
    exec_command("dpkg-reconfigure -f noninteractive unattended-upgrades")

def setup_security_cron_jobs():
    status_gui.update_status("Setting up security automation...")
    cron_jobs = [
        "@daily apt update && apt upgrade -y",
        "@weekly lynis audit system >> /var/log/lynis_weekly.log",
        "@weekly find / -perm -2000 -type f -exec ls -ld {} \\; > ~/setgid_permissions.txt"
    ]
    for job in cron_jobs:
        exec_command(f"(crontab -l 2>/dev/null; echo \"{job}\") | crontab -")

# RUN SECURITY AUDITS 
def run_audits():
    """Runs security audits with progress tracking, ensuring freshclam runs last."""
    total_steps = 4  # steps
    current_step = 0

    def update_progress(task_name):
        """Helper function to update progress dynamically."""
        nonlocal current_step
        current_step += 1
        progress_percent = int((current_step / total_steps) * 100)
        status_gui.update_status(f"{task_name} in progress... ({progress_percent}%)", progress_percent)
        
# UPDATE LYNIS and push CLAMV
    def run_audits():
    """Runs security audits with progress tracking, ensuring freshclam runs last, and sets a timeout for ClamAV."""
    total_steps = 4  
    current_step = 0

    def update_progress(task_name):
        """Helper function to update progress dynamically."""
        nonlocal current_step
        current_step += 1
        progress_percent = int((current_step / total_steps) * 100)
        status_gui.update_status(f"{task_name} in progress... ({progress_percent}%)", progress_percent)

    # 1: CHECK & UPDATE LYNIS
    update_progress("Checking for Lynis updates...")
    lynis_version = exec_command("lynis show version")
    if not lynis_version or "command not found" in lynis_version.lower():
        status_gui.update_status("Lynis is not installed. Installing now...")
        exec_command("apt install -y lynis")
    else:
        exec_command("apt update && apt install --only-upgrade -y lynis")

    # 2: RUN LYNIS FIRST
    update_progress("Running Lynis Security Audit")
    exec_command("lynis audit system --quick | tee /var/log/lynis_audit.log")

    # 3: RUN CLAMAV SCAN -TIMEOUT 
    update_progress("Scanning system with ClamAV")
    log_file = f"/var/log/clamav_scan_{DATE}.log"

    def run_clamscan():
        """Runs ClamAV scan with a timeout to prevent freezing."""
        try:
            exec_command(f"timeout 600 clamscan -r /home --infected --log={log_file}") 
        except Exception as e:
            logging.error(f"ClamAV scan failed: {e}")
            status_gui.update_status("ClamAV scan encountered an issue. Check logs.")

    threading.Thread(target=run_clamscan, daemon=True).start()  

    # 4: RUN FRESHCLAM LAST (In Separate Thread)
    def run_freshclam():
        update_progress("Updating ClamAV database (Freshclam)")
        exec_command("freshclam")
        status_gui.update_status("Security Audits Completed!", 100)  

    threading.Thread(target=run_freshclam, daemon=True).start()  


# MAIN FUNCTION
def start_hardening():
    def run_hardening():
        configure_firewall()
        enforce_password_policies()
        track_setgid_permissions()
        enable_auto_updates()
        setup_security_cron_jobs()
        configure_kernel_security() # GRUB SHOULD BE FIRST
        configure_fail2ban()
        run_audits()  

        status_gui.complete()  

    threading.Thread(target=run_hardening, daemon=True).start()


def main():
    print_ascii_art()
    signal.signal(signal.SIGINT, clean_exit)  
    status_gui.root.after(100, start_hardening)
    status_gui.run()


if __name__ == "__main__":
    main()
