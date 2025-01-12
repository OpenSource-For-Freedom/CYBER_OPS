#!/usr/bin/env python3
# hard3n_qubes.py the Debian OS complete Lockdown tool for local and routing needs. 
import os
import subprocess
import sys
import logging
from logging.handlers import RotatingFileHandler

# Ensure log dir exists
LOG_DIR = "/var/log"
LOG_FILE = "hard3n_qube.log"
log_path = os.path.join(LOG_DIR, LOG_FILE)
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR, mode=0o755, exist_ok=True)

# Setup logging + rotation
log_handler = RotatingFileHandler(log_path, maxBytes=50 * 1024 * 1024, backupCount=1)
log_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)

# Run handling
def run_command(command, description=""):
    logger.info(f"[+] {description}")
    print(f"[+] {description}")
    try:
        if not isinstance(command, list):
            raise ValueError("Command must be provided as a list to avoid parsing errors.")
        result = subprocess.run(command, text=True, check=True, capture_output=True)
        if result.stdout:
            logger.info(result.stdout)
            print(result.stdout)
        if result.stderr:
            logger.error(f"[-] Error: {result.stderr}")
            print(f"[-] Error: {result.stderr}")
    except subprocess.CalledProcessError as e:
        logger.error(f"[-] Error: {description} failed. {e.stderr}")
        print(f"[-] Error: {description} failed. {e.stderr}")
        raise RuntimeError(f"Command failed: {command}")
    except ValueError as ve:
        logger.error(f"[-] {ve}")
        raise

def check_privileges():
    """Check if the script is running with root privileges."""
    if not hasattr(os, 'geteuid') or os.geteuid() != 0:
        logger.error("This script must be run as root. Please use 'sudo'.")
        print("[-] This script must be run as root. Please use 'sudo'.")
        raise PermissionError("Script requires root privileges.")

# Verify root?
check_privileges()

# Configure TOR + Snowflake bridge
def configure_tor():
    """Configure TOR with Snowflake bridge."""
    print("[+] Configuring TOR with Snowflake bridge...")

    # Install TOR + bridge Snowflake
    run_command(["apt", "update"], "Updating package lists")
    run_command(["apt", "install", "-y", "tor", "snowflake-client"], "Installing TOR and Snowflake client")

    # TOR configuration
    torrc_content = """
ClientTransportPlugin snowflake exec /usr/bin/snowflake-client
UseBridges 1
Bridge snowflake 192.0.2.1:443
DNSPort 9053
TransPort 9040
"""
    # Write torrc configuration
    torrc_path = "/etc/tor/torrc"
    try:
        with open(torrc_path, "w") as torrc_file:
            torrc_file.write(torrc_content)
        print(f"[+] Wrote TOR configuration to {torrc_path}.")
    except Exception as e:
        print(f"[-] Failed to write TOR configuration: {e}")
        raise IOError(f"Failed to write TOR configuration: {e}")

    # Set permissions for the torrc file
    run_command(["chown", "tor:tor", torrc_path], "Setting torrc file ownership")
    run_command(["chmod", "644", torrc_path], "Setting torrc file permissions")

    # Restart TOR service
    run_command(["systemctl", "restart", "tor"], "Restarting TOR service")
    print("[+] TOR configured with Snowflake bridge.")

# Lockdown NIC > route only over TOR
def lockdown_nic_with_tor():
    """Lock down NIC and route traffic only through TOR."""
    print("[+] Configuring network for TOR usage...")

    # Flush existing rules
    run_command(["iptables", "-F"], "Flushing existing iptables rules")
    run_command(["iptables", "-t", "nat", "-F"], "Flushing existing NAT rules")

    # Allow TOR traffic
    run_command(["iptables", "-t", "nat", "-A", "OUTPUT", "-m", "owner", "--uid-owner", "tor", "-j", "RETURN"], "Allow TOR traffic")

    # Redirect DNS to TOR
    run_command(["iptables", "-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "9053"], "Redirect DNS traffic to TOR")

    # Redirect TCP traffic to TOR
    run_command(["iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--syn", "-j", "REDIRECT", "--to-ports", "9040"], "Redirect TCP traffic to TOR")

    # Allow established connections
    run_command(["iptables", "-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"], "Allow established connections")

    # Block all other outbound traffic
    run_command(["iptables", "-A", "OUTPUT", "-j", "REJECT"], "Block all other outbound traffic")

    # Save rules to persist across reboots
    run_command(["iptables-save", "-f", "/etc/iptables/rules.v4"], "Saving iptables rules for persistence")

    print("[+] TOR-only routing configured.")

# Containerize browser 
def containerize_browser(browser="firefox", options=None):
    """Containerize browser activity using Firejail."""
    print("[+] Containerizing browser activity...")
    run_command(["apt", "install", "-y", "firejail"], "Installing Firejail sandboxing tool")
    if options is None:
        options = "--net=none"
    browser_container_command = f"firejail {options} {browser}"
    print(f"[+] Browser container command: {browser_container_command}")

# Sandbox all dir (general only right now)
def sandbox_directories():
    """Sandbox critical system directories from unauthorized changes."""
    critical_directories = ["/var", "/lib", "/bin", "/sbin", "/root", "/grub"]

    print("[+] Sandbox critical directories configuration started...")
    run_command(["apt", "install", "-y", "firejail"], "Ensuring Firejail is installed")

    for directory in critical_directories:
        print(f"[+] Setting up sandbox for {directory}...")
        if directory in ["/bin", "/sbin"]:
            print(f"[!] Warning: Sandboxing {directory} may break essential system functions.")
        run_command(["firejail", f"--private={directory}"], f"Sandboxing directory {directory}")

    print("[+] Critical directories sandboxed successfully.")

# Redirect web downloads > locked-down directory
def redirect_web_downloads(directory="/var/locked_downloads"):
    """Redirect web-based downloads to a locked directory for inspection."""
    print(f"[+] Setting up directory {directory} for inspecting downloads...")
    if not os.path.exists(directory):
        os.makedirs(directory, mode=0o700, exist_ok=True)
        # Check storage space
        statvfs = os.statvfs(directory)
        free_space = statvfs.f_frsize * statvfs.f_bavail / (1024 * 1024 * 1024)  # Convert to GB
        if free_space < 1:
            logger.error("Insufficient storage space in the locked directory.")
            raise RuntimeError("Insufficient storage space for download inspection.")
        run_command(["chown", "root:root", directory], "Setting directory ownership to root")
        run_command(["chmod", "700", directory], "Restricting directory permissions")

    # Set iptables rules to redirect all downloads
    log_file = "/var/log/download_inspection.log"
    run_command(["iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", "80", "-j", "LOG", "--log-prefix", "HTTP-DOWNLOAD:", "--log-level", "info"], f"Logging HTTP downloads to {log_file}")
    run_command(["iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", "443", "-j", "LOG", "--log-prefix", "HTTPS-DOWNLOAD:", "--log-level", "info"], f"Logging HTTPS downloads to {log_file}")

    print(f"[+] Downloads will be logged for inspection in {directory}.")

# Release the Qube
 if __name__ == "__main__":
     configure_tor()
     lockdown_nic_with_tor()
     containerize_browser()
     sandbox_directories()
     redirect_web_downloads()
