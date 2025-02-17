import os
import subprocess
import shutil
import sys
import signal
import logging
from datetime import datetime
import tkinter as tk
from hard3n_tk import Hard3nGUI  # import GUI

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
    
    # Status Counter that should work... should
status_step = 0  # Global variable to track progress
total_steps = 6   # Adjust this number based on your steps

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


def is_root_user():
    if os.geteuid() != 0:
        log("Error: Please run this script with sudo or as root.")
        exit(1)


# Functionality CPU mits an grub boop
def enable_cpu_mitigations():
    update_status("Enabling CPU Mitigations")
    exec_command("cp /etc/default/grub /etc/default/grub.bak")
    exec_command(
        'sed -i \'/^GRUB_CMDLINE_LINUX=/ s/"$/ mitigations=auto spectre_v2=on spec_store_bypass_disable=on '
        'l1tf=full,force mds=full tsx=off tsx_async_abort=full l1d_flush=on mmio_stale_data=full retbleed=auto"/\' '
        '/etc/default/grub'
    )
    exec_command("update-grub")
    log("CPU mitigations enabled and GRUB configuration updated successfully.")

    
# UFW stuff
def configure_firewall(ssh_needed, ssh_port=22, ssh_out_port=22):
    update_status("Configuring Firewall")
    exec_command("sudo ufw enable")
    exec_command("sudo ufw default deny incoming")
    exec_command("sudo ufw default allow outgoing")

    if ssh_needed:
        exec_command(f"sudo ufw allow {ssh_port}")
        exec_command(f"sudo ufw allow out {ssh_out_port}")
        log(f"SSH access allowed on ports {ssh_port} (inbound) and {ssh_out_port} (outbound).")
    else:
        log("SSH access disabled.")

# Install Sec tools and upgrade OS
def install_security_tools():
    log("Updating system packages...")
    exec_command("apt update")
    exec_command("apt upgrade -y")

    log("Installing security tools...")
    exec_command("apt install -y podman firejail bubblewrap ufw fail2ban clamav lynis apparmor apparmor-utils libpam-google-authenticator")

# I would like to impliment a lcoal user MFA but... that may be too much at this time
# def configure_mfa():
#    log("Configuring Google MFA for SSH login...")
#   with open("/etc/pam.d/sshd", "a") as pam_file:
 #       pam_file.write("auth required pam_google_authenticator.so\n")
#
 #   exec_command(r"sed -i 's/^#ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config")
  #  exec_command(r"sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config")
   # exec_command(r"sed -i 's/^UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config")
    #exec_command("systemctl restart sshd")
  #  log("Google MFA configured. Users should run 'google-authenticator' to set up their accounts.")

# OS sandboxing for web browsers
def setup_sandboxing():
    update_status("Configuring Browser Sandboxing")
    user_home = os.path.expanduser("~" + os.getenv("SUDO_USER", os.getenv("USER", "")))

    browser_map = {
        "firefox": (f"{user_home}/.mozilla", "/usr/bin/firefox"),
        "google-chrome": (f"{user_home}/.config/google-chrome", "/usr/bin/google-chrome"),
        "chromium-browser": (f"{user_home}/.config/chromium", "/usr/bin/chromium-browser"),
        "chromium": (f"{user_home}/.config/chromium", "/usr/bin/chromium"),
        "brave-browser": (f"{user_home}/.config/BraveSoftware", "/usr/bin/brave-browser"),
        "opera": (f"{user_home}/.config/opera", "/usr/bin/opera"),
    }

    for browser, (profile_dir, binary_path) in browser_map.items():
        if shutil.which(browser):
            log(f"Configuring Bubblewrap sandbox for {browser}...")
            
            # Ensure the dir exists before committing (seems bwrap got lost on firefox and couldnt move)
            if os.path.exists(profile_dir):
                exec_command(
                    f"bwrap --ro-bind / / --dev /dev --proc /proc --unshare-all "
                    f"--bind {profile} {profile} -- {browser}"
                )
            else:
                log(f"{browser} profile directory not found at {profile}, skipping sandboxing.")
        else:
            log(f"{browser} not found, skipping sandboxing.")


# clamv + lynis background scan
def run_audits():n
    update_status("Running Security Audits")

    log("Setting up ClamAV...")
    exec_command("freshclam")

    scan_dirs = ["/home", "/var/log", "/etc", "/usr/bin"]

    log("Starting ClamAV scan in the background...")
    for dir in scan_dirs:
        log(f"Scanning {dir} with ClamAV...")
        exec_command(f"clamscan -r {dir} --log={LOG_DIR}/clamav_scan_{DATE}.log")
    
    log("Running Lynis system audit...")
    exec_command(f"lynis audit system | tee {LOG_DIR}/lynis_audit_{DATE}.log")


# Main Script Execution
def main():
    is_root_user()
    log("Starting system hardening...")

    enable_cpu_mitigations()
    install_security_tools()

    ssh_needed = input("Do you need SSH access? (y/n): ").strip().lower() == "y"
    ssh_port = 22
    ssh_out_port = 22

    if ssh_needed:
        ssh_port = input("Enter inbound port for SSH (default 22): ").strip() or 22
        ssh_out_port = input("Enter outbound port for SSH (default 22): ").strip() or 22

    configure_firewall(ssh_needed, ssh_port, ssh_out_port)
    #configure_mfa()
    setup_sandboxing()
    run_audits()

    log("System hardening complete. Please reboot the system for all changes to take effect.")
    if input("Would you like to reboot now? (y/n): ").strip().lower() == "y":
        exec_command("reboot")

  # Ask user about Hard3n Qube script GUI
    gui = Hard3nGUI()
    gui.run()  # Run the GUI after full sript is completed

if __name__ == "__main__":
    main()
