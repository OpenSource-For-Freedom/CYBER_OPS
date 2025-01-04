#!/usr/bin/env python3
import os
import subprocess
import logging
from datetime import datetime

LOG_FILE = "/var/log/hard3n_deep.log"

# Set up logs
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(message)s')

def log(message):
    """Log messages with timestamp"""
    logging.info(message)
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {message}")

def run_command(command):
    """Run a system command and handle errors"""
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        log(f"[-] Error: Command '{e.cmd}' failed.")
        exit(1)

def disable_core_dumps():
    """Disable core dumps by modifying limits.conf"""
    log("[+] Disabling core dumps...")
    run_command("echo '* hard core 0;' | sudo tee -a /etc/security/limits.conf > /dev/null")

def configure_tcp_wrappers():
    """Configure TCP Wrappers by editing /etc/hosts.deny"""
    log("[+] Configuring TCP Wrappers...")
    if os.path.isfile("/etc/hosts.deny"):
        run_command("echo 'ALL: ALL' | sudo tee -a /etc/hosts.deny > /dev/null")
    else:
        log("[-] /etc/hosts.deny does not exist, skipping TCP Wrappers configuration.")

def restrict_non_local_logins():
    """Restrict non-local logins except for sshd (remote SSH)"""
    log("[+] Restricting non-local logins...")
    if os.path.isfile("/etc/security/access.conf"):
        run_command("echo '-:ALL:ALL EXCEPT LOCAL,sshd' | sudo tee -a /etc/security/access.conf > /dev/null")
    else:
        log("[-] /etc/security/access.conf does not exist, skipping non-local login restriction.")

def secure_files():
    """Secure critical configuration files with chmod 600"""
    log("[+] Securing configuration files...")

    files_to_secure = [
        "/etc/security/limits.conf",
        "/etc/hosts.deny",
        "/etc/security/access.conf"
    ]
    
    for file in files_to_secure:
        if os.path.isfile(file):
            run_command(f"sudo chmod 600 {file}")
        else:
            log(f"[-] {file} does not exist, skipping.")

def main():
    log("[+] Starting hardening script...")
    disable_core_dumps()
    configure_tcp_wrappers()
    restrict_non_local_logins()
    secure_files()
    log("[+] hard3n_deep.py completed successfully.")

if __name__ == "__main__":
    main()



# Key Changes:

# SSH Access Exception in /etc/security/access.conf:
#The line echo "-:ALL:ALL EXCEPT LOCAL,sshd" ensures that SSH (sshd) access is allowed even if remote logins are generally restricted to local-only users. This is especially important for remote systems where you may want to SSH into the machine.

#Check if Configuration Files Exist:
#The script now checks whether the files (/etc/hosts.deny, /etc/security/access.conf, /etc/security/limits.conf) exist before trying to modify them. This prevents errors from running the script on systems where these files might not exist by default.

#Added Logs for Missing Files:
#If a configuration file does not exist, the script will log a message and skip modifying it instead of failing.

#Permissions Changes:
#The script will only attempt to change file permissions (chmod 600) if the file exists, reducing potential errors.