import subprocess
import sys
import os
from datetime import datetime

# Define log directory and file
LOG_DIR = "/var/log/security_scans"
os.makedirs(LOG_DIR, exist_ok=True)
DATE = datetime.now().strftime("%Y%m%d_%H%M%S")
SCRIPT_LOG = os.path.join(LOG_DIR, f"script_execution_{DATE}.log")

# Log function
def log(message):
    with open(SCRIPT_LOG, 'a') as f:
        f.write(f"{datetime.now().strftime('%Y-%m-%d %T')} {message}\n")
    print(message)

# Function to execute a shell command and check success
def exec_e(command):
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        log(f"Command succeeded: {command}")
        return result.stdout.decode()
    except subprocess.CalledProcessError as e:
        log(f"Error executing command: {command}\n{e.stderr.decode()}")
        sys.exit(1)

# Function to check if a package is installed
def is_package_installed(package_name):
    result = subprocess.run(f"dpkg -l {package_name}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return "ii" in result.stdout.decode()

# Update system packages
log("Updating system packages...")
exec_e("sudo apt update && sudo apt upgrade -yy")

# Install security tools
log("Installing security tools...")
security_tools = [
    "podman", "lxd", "lxd-client", "firejail", "bubblewrap", 
    "ufw", "fail2ban", "clamav", "lynis", "apparmor", "apparmor-utils"
]
for tool in security_tools:
    exec_e(f"sudo apt install -yy {tool}")

# Enable AppArmor
log("Enabling AppArmor...")
exec_e("sudo systemctl enable --now apparmor")

# Enable UFW (Uncomplicated Firewall)
log("Setting up UFW firewall...")
exec_e("sudo ufw enable")
exec_e("sudo ufw default deny incoming")
exec_e("sudo ufw default allow outgoing")

# SSH Configuration
ssh_needed = input("Do you need SSH access? (y/n): ").lower()
if ssh_needed == "y":
    ssh_port = input("Enter inbound port for SSH (default 22): ") or "22"
    ssh_out_port = input("Enter outbound port for SSH (default 22): ") or "22"
    log(f"Allowing SSH inbound and outbound on ports {ssh_port} and {ssh_out_port}")
    exec_e(f"sudo ufw allow {ssh_port}")
    exec_e(f"sudo ufw allow out {ssh_out_port}")
else:
    log("SSH access is disabled.")

# Enable Fail2Ban
log("Enabling Fail2Ban...")
exec_e("sudo systemctl enable --now fail2ban")

# Install and configure ClamAV
log("Setting up ClamAV...")
exec_e("sudo freshclam")
exec_e(f"sudo clamscan -r / --log={LOG_DIR}/clamav_scan_{DATE}.log")

# Run system audit with Lynis
log("Running Lynis system audit...")
exec_e(f"sudo lynis audit system | tee {LOG_DIR}/lynis_audit_{DATE}.log")

# Podman containerization (Firefox example)
log("Setting up Podman for Firefox container...")
if not is_package_installed("podman"):
    log("Podman not installed, installing...")
    exec_e("sudo apt install -yy podman")

# Pull Firefox container image
log("Pulling Firefox container image...")
exec_e("sudo podman pull jess/firefox")

# Run Firefox in a container with network isolation
log("Running Firefox in a container (network isolation)...")
exec_e("sudo podman run -it --rm --net=none jess/firefox")

# LXC/LXD containerization (System containers)
log("Setting up LXC/LXD containers...")
if not is_package_installed("lxd"):
    log("LXD not installed, installing...")
    exec_e("sudo apt install -yy lxd lxd-client")
    exec_e("sudo lxd init --auto")

# Create an LXC container for Firefox
log("Creating LXC container for Firefox...")
exec_e("sudo lxc launch ubuntu:20.04 firefox-container")
exec_e("sudo lxc exec firefox-container -- apt update && sudo apt install -yy firefox")
exec_e("sudo lxc exec firefox-container -- firefox")

# Firejail sandboxing for applications
log("Setting up Firejail sandbox for Firefox...")
exec_e("firejail firefox")

# Bubblewrap sandboxing
log("Setting up Bubblewrap for Firefox...")
exec_e(f"bwrap --ro-bind / / --dev /dev --proc /proc --unshare-all --bind /home/$USER/.mozilla /home/$USER/.mozilla --bind /tmp /tmp -- /usr/bin/firefox")

# Final Notification and Reboot
log("System hardening complete. All security measures are now in place.")
reboot_now = input("MUST reboot to apply HARD3N8 updates and changes? (y/n): ").lower()
if reboot_now == "y":
    exec_e("sudo reboot")
else:
    log("Reboot the system to ensure all packages, files, and containerization can take full effect.")
