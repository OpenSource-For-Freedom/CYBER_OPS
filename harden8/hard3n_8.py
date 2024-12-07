import subprocess
import sys
import os
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, simpledialog
# added tkinter for gui message box for user

# Def log directory and file
LOG_DIR = "/var/log/security_scans"
os.makedirs(LOG_DIR, exist_ok=True)
DATE = datetime.now().strftime("%Y%m%d_%H%M%S")
SCRIPT_LOG = os.path.join(LOG_DIR, f"script_execution_{DATE}.log")

# Log function
def log(message):
    with open(SCRIPT_LOG, 'a') as f:
        f.write(f"{datetime.now().strftime('%Y-%m-%d %T')} {message}\n")
    print(message)

# execute a shell command check success
def exec_e(command):
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        log(f"Command succeeded: {command}")
        return result.stdout.decode()
    except subprocess.CalledProcessError as e:
        log(f"Error executing command: {command}\n{e.stderr.decode()}")
        sys.exit(1)

# check if a package is installed
def is_package_installed(package_name):
    result = subprocess.run(f"dpkg -l {package_name}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return "ii" in result.stdout.decode()

# execute the "hard3n8_deep.sh" script
def run_hard3n8_deep():
    log("Running additional hardening script 'hard3n8_deep.sh'...")
    script_path = "/path/to/hard3n8_deep.sh"  # Replace with the actual path to the script
    exec_e(f"sudo bash {script_path}")
    show_message("Hardening", "'hard3n8_deep.sh' script executed successfully!")

# update system packages
def update_system():
    log("Updating system packages...")
    exec_e("sudo apt update && sudo apt upgrade -yy")
    show_message("System Update", "System packages updated successfully!")

# install security tools
def install_security_tools():
    log("Installing security tools...")
    security_tools = [
        "podman", "lxd", "lxd-client", "firejail", "bubblewrap", 
        "ufw", "fail2ban", "clamav", "lynis", "apparmor", "apparmor-utils"
    ]
    for tool in security_tools:
        exec_e(f"sudo apt install -yy {tool}")
    show_message("Security Tools Installation", "Security tools installed successfully!")

# Function to enable AppArmor
def enable_apparmor():
    log("Enabling AppArmor...")
    exec_e("sudo systemctl enable --now apparmor")
    show_message("AppArmor", "AppArmor enabled successfully!")

# configure UFW firewall
def setup_ufw():
    log("Setting up UFW firewall...")
    exec_e("sudo ufw enable")
    exec_e("sudo ufw default deny incoming")
    exec_e("sudo ufw default allow outgoing")
    show_message("UFW Setup", "UFW Install3d successfully!")

# Function to configure SSH access
def configure_ssh():
    ssh_needed = ask_question("Do you need SSH access?")
    if ssh_needed == "yes":
        ssh_port = ask_input("Enter inbound port for SSH (default 22): ") or "22"
        ssh_out_port = ask_input("Enter outbound port for SSH (default 22): ") or "22"
        log(f"Allowing SSH inbound and outbound on ports {ssh_port} and {ssh_out_port}")
        exec_e(f"sudo ufw allow {ssh_port}")
        exec_e(f"sudo ufw allow out {ssh_out_port}")
        show_message("SSH Configuration", "SSH access configured successfully!")
    else:
        log("SSH access is disabled.")

# enable Fail2Ban
def enable_fail2ban():
    log("Enabling Fail2Ban...")
    exec_e("sudo systemctl enable --now fail2ban")
    show_message("Fail2Ban", "Fail2Ban enabled successfully!")

# setup ClamAV
def setup_clamav():
    log("Setting up ClamAV...")
    exec_e("sudo freshclam")
    exec_e(f"sudo clamscan -r / --log={LOG_DIR}/clamav_scan_{DATE}.log")
    show_message("ClamAV Setup", "ClamAV scan completed successfully!")

# Lynis audit
def run_lynis():
    log("Running Lynis system audit...")
    exec_e(f"sudo lynis audit system | tee {LOG_DIR}/lynis_audit_{DATE}.log")
    show_message("Lynis Audit", "Lynis system audit completed successfully!")

# Podman containerization
def setup_podman():
    log("Setting up Podman for Firefox container...")
    if not is_package_installed("podman"):
        log("Podman not installed, installing...")
        exec_e("sudo apt install -yy podman")
    exec_e("sudo podman pull jess/firefox")
    exec_e("sudo podman run -it --rm --net=none jess/firefox")
    show_message("Podman Setup", "Podman container for Firefox created successfully!")

# LXC containerization
def setup_lxc():
    log("Setting up LXC/LXD containers...")
    if not is_package_installed("lxd"):
        log("LXD not installed, installing...")
        exec_e("sudo apt install -yy lxd lxd-client")
        exec_e("sudo lxd init --auto")
    exec_e("sudo lxc launch ubuntu:20.04 firefox-container")
    exec_e("sudo lxc exec firefox-container -- apt update && sudo apt install -yy firefox")
    exec_e("sudo lxc exec firefox-container -- firefox")
    show_message("LXC Setup", "LXC container for Firefox created successfully!")

# Firejail sandbox
def setup_firejail():
    log("Setting up Firejail sandbox for Firefox...")
    exec_e("firejail firefox")
    show_message("Firejail Setup", "Firejail sandbox configured successfully!")

# Bubblewrap sandbox
def setup_bubblewrap():
    log("Setting up Bubblewrap for Firefox...")
    exec_e(f"bwrap --ro-bind / / --dev /dev --proc /proc --unshare-all --bind /home/$USER/.mozilla /home/$USER/.mozilla --bind /tmp /tmp -- /usr/bin/firefox")
    show_message("Bubblewrap Setup", "Bubblewrap sandbox configured successfully!")

# reboot system
def reboot_system():
    reboot_now = ask_question("Do you want to reboot the system now?")
    if reboot_now == "yes":
        exec_e("sudo reboot")
    else:
        log("Reboot deferred. Please reboot later to apply all changes.")

# Tkinter prompt Yes/No questions
def ask_question(question):
    answer = messagebox.askyesno("Question", question)
    return "yes" if answer else "no"

# Tkinter prompt for input
def ask_input(prompt):
    return simpledialog.askstring("Input", prompt)

# show a message box
def show_message(title, message):
    messagebox.showinfo(title, message)

# check if Tkinter is installed
def ensure_tkinter_installed():
    try:
        import tkinter
    except ImportError:
        log("Tkinter is not installed. Installing Tkinter...")
        exec_e("sudo apt install python3-tk")
        log("Tkinter installed successfully.")

# run the setup
def run_security_setup():
    ensure_tkinter_installed()
    update_system()
    install_security_tools()
    enable_apparmor()
    setup_ufw()
    configure_ssh()
    enable_fail2ban()
    setup_clamav()
    run_lynis()
    setup_podman()
    setup_lxc()
    setup_firejail()
    setup_bubblewrap()
    run_hard3n8_deep()  # Add the call to the additional hardening script in local
    reboot_system()

# Tkinter GUI setup
def create_gui():
    root = tk.Tk()
    root.title("System Hardening Setup")
    root.geometry("400x200")

    # Start Button to begin the setup process
    start_button
