import os
import subprocess
import shutil
import sys
import logging
from datetime import datetime
import argparse

# Print the ASCII art and text
def print_ascii_art():
    art = """
        -----------------------------------------------------------------------
                    H   H   AAAAA   RRRR    DDDD    333333    NN    N
          ======== H   H  A     A  R   R   D   D       33    N N   N ========
          ======= HHHHH  AAAAAAA  RRRR    D   D     33      N  N  N =========
          ====== H   H  A     A  R  R    D   D       33    N   N N ==========
                H   H  A     A  R   R   DDDD    333333    N    NN
        -----------------------------------------------------------------------
                    "HARD3N" - The Linux Security Project
                    ----------------------------------------
                     A project focused on improving Linux
                    security by automating, containerizing
                                Hardening and
                         System protection measures.
                             License: MIT License
                                Version: 1.3.1
                               Dev: Tim Burns
          GitHub: https://github.com/OpenSource-For-Freedom/Linux.git
    """
    print(art)
import os
import subprocess
import logging
from datetime import datetime
import tkinter as tk
from hard3n_tk import Hard3nGUI # import GUI

# Configure logging
LOG_DIR = "/var/log/security_scans"
os.makedirs(LOG_DIR, exist_ok=True)
DATE = datetime.now().strftime("%Y%m%d_%H%M%S")
SCRIPT_LOG = os.path.join(LOG_DIR, f"script_execution_{DATE}.log")

logging.basicConfig(
    filename=SCRIPT_LOG,
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# add tkinter function to ask us3rs if they want to import
# dependant files _qubes.py and _dark.py using a simple branded GUI

# Helper Functions
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


# Functionality Implementations
def enable_cpu_mitigations():
    log("Enabling known mitigations for CPU vulnerabilities...")
    exec_command("cp /etc/default/grub /etc/default/grub.bak")
    exec_command(
        r'sed -i \'s|GRUB_CMDLINE_LINUX="|GRUB_CMDLINE_LINUX="mitigations=auto spectre_v2=on '
        r'spec_store_bypass_disable=on l1tf=full,force mds=full tsx=off tsx_async_abort=full '
        r'kvm.nx_huge_pages=force l1d_flush=on mmio_stale_data=full retbleed=auto |\' /etc/default/grub'
    )
    exec_command("update-grub")
    log("CPU mitigations enabled and GRUB configuration updated.")


def configure_firewall(ssh_needed, ssh_port=22, ssh_out_port=22):
    log("Setting up UFW firewall...")
    exec_command("ufw enable")
    exec_command("ufw default deny incoming")
    exec_command("ufw default allow outgoing")

    if ssh_needed:
        exec_command(f"ufw allow {ssh_port}")
        exec_command(f"ufw allow out {ssh_out_port}")
        log(f"SSH access allowed on ports {ssh_port} (inbound) and {ssh_out_port} (outbound).")
    else:
        log("SSH access disabled.")


def install_security_tools():
    log("Updating system packages...")
    exec_command("apt update")
    exec_command("apt upgrade -yy")

    log("Installing security tools...")
    exec_command("apt install -yy podman firejail bubblewrap ufw fail2ban clamav lynis apparmor apparmor-utils libpam-google-authenticator")


def configure_mfa():
    log("Configuring Google MFA for SSH login...")
    with open("/etc/pam.d/sshd", "a") as pam_file:
        pam_file.write("auth required pam_google_authenticator.so\n")

    exec_command(r"sed -i 's/^#ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config")
    exec_command(r"sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config")
    exec_command(r"sed -i 's/^UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config")
    exec_command("systemctl restart sshd")
    log("Google MFA configured. Users should run 'google-authenticator' to set up their accounts.")


def setup_sandboxing():
    log("Configuring sandboxing tools for web browsers...")
    browser_map = {
        "firefox": ("/home/$USER/.mozilla", "/usr/bin/firefox"),
        "google-chrome": ("/home/$USER/.config/google-chrome", "/usr/bin/google-chrome"),
        "chromium-browser": ("/home/$USER/.config/chromium", "/usr/bin/chromium-browser"),
        "chromium": ("/home/$USER/.config/chromium", "/usr/bin/chromium"),
        "brave-browser": ("/home/$USER/.config/BraveSoftware", "/usr/bin/brave-browser"),
        "opera": ("/home/$USER/.config/opera", "/usr/bin/opera")
    }

    for browser, (profile_dir, binary_path) in browser_map.items():
        if shutil.which(browser):
            log(f"Configuring Bubblewrap sandbox for {browser}...")
            exec_command(
                f"bwrap --ro-bind / / --dev /dev --proc /proc --unshare-all "
                f"--bind {profile_dir} {profile_dir} --bind /tmp /tmp -- {binary_path}"
            )
        else:
            log(f"{browser} not found, skipping Bubblewrap sandboxing.")


def run_audits():
    log("Setting up ClamAV...")
    exec_command("freshclam")
    exec_command(f"clamscan -r / --log={LOG_DIR}/clamav_scan_{DATE}.log")

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
    configure_mfa()
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
