import os
import shutil
import subprocess
import logging
from datetime import datetime
import argparse

LOG_FILE = "/var/log/hardn_deep.log"

# Set up logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")

def log(message):
    """Log messages with timestamp"""
    logging.info(message)
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {message}")

def run_command(command, test_mode=False):
    """Run a system command and handle errors"""
    if test_mode:
        log(f"[TEST MODE] Would run: {command}")
        return
    try:
        subprocess.run(command, shell=True, check=True, text=True)
    except subprocess.CalledProcessError as e:
        log(f"[-] Error: Command '{e.cmd}' failed.")
        exit(1)

def is_command_available(command):
    """Check if a command is available on the system"""
    return shutil.which(command) is not None

def backup_file(file_path, test_mode=False):
    """Create a backup of the file"""
    if os.path.isfile(file_path):
        backup_path = f"{file_path}.bak"
        if test_mode:
            log(f"[TEST MODE] Would create backup for {file_path} -> {backup_path}")
        else:
            shutil.copy(file_path, backup_path)
            log(f"[+] Backup created: {file_path} -> {backup_path}")
    else:
        log(f"[-] {file_path} does not exist, skipping backup.")

def disable_core_dumps(test_mode=False):
    """Disable core dumps by modifying limits.conf"""
    log("[+] Disabling core dumps...")
    backup_file("/etc/security/limits.conf", test_mode)
    run_command("echo '* hard core 0;' | sudo tee -a /etc/security/limits.conf > /dev/null", test_mode)

def configure_tcp_wrappers(test_mode=False):
    """Configure TCP Wrappers by editing /etc/hosts.deny"""
    log("[+] Configuring TCP Wrappers...")
    if os.path.isfile("/etc/hosts.deny"):
        backup_file("/etc/hosts.deny", test_mode)
        run_command("echo 'ALL: ALL' | sudo tee -a /etc/hosts.deny > /dev/null", test_mode)
    else:
        log("[-] /etc/hosts.deny does not exist, skipping TCP Wrappers configuration.")

def restrict_non_local_logins(test_mode=False):
    """Restrict non-local logins except for sshd (remote SSH)"""
    log("[+] Restricting non-local logins...")
    if os.path.isfile("/etc/security/access.conf"):
        backup_file("/etc/security/access.conf", test_mode)
        run_command("echo '-:ALL:ALL EXCEPT LOCAL,sshd' | sudo tee -a /etc/security/access.conf > /dev/null", test_mode)
    else:
        log("[-] /etc/security/access.conf does not exist, skipping non-local login restriction.")

def secure_files(test_mode=False):
    """Secure critical configuration files with chmod 600"""
    log("[+] Securing configuration files...")

    files_to_secure = [
        "/etc/security/limits.conf",
        "/etc/hosts.deny",
        "/etc/security/access.conf"
    ]
    
    for file in files_to_secure:
        if os.path.isfile(file):
            backup_file(file, test_mode)
            run_command(f"sudo chmod 600 {file}", test_mode)
        else:
            log(f"[-] {file} does not exist, skipping.")

def main():
    # Argument parsing
    parser = argparse.ArgumentParser(description="Hardn Security Hardening Script")
    parser.add_argument("--test", action="store_true", help="Run in test mode without applying changes")
    args = parser.parse_args()
    test_mode = args.test

    log("[+] Starting hardening script...")
    if test_mode:
        log("[TEST MODE] No changes will be applied. This is a dry run.")

    # Hardening steps
    disable_core_dumps(test_mode)
    configure_tcp_wrappers(test_mode)
    restrict_non_local_logins(test_mode)
    secure_files(test_mode)

    log("[+] hardn_dark.py completed successfully.")

    if __name__ == "__main__":
        main()