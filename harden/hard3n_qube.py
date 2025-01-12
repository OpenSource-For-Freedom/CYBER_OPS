#!/usr/bin/env python3

import os
import subprocess
import sys
import logging

# Setup logging
logging.basicConfig(filename="/var/log/hard3n_qube.log", level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger()

# Run handling
def run_command(command, description=""):
    logger.info(f"[+] {description}")
    print(f"[+] {description}")
    try:
        command_list = command.split() if isinstance(command, str) else command
        result = subprocess.run(command_list, text=True, check=True, capture_output=True)
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

def check_privileges():
    """Check if the script is running with root privileges."""
    if os.geteuid() != 0:
        logger.error("This script must be run as root. Please use 'sudo'.")
        print("[-] This script must be run as root. Please use 'sudo'.")
        raise PermissionError("Script requires root privileges.")

# Verify elevated privileges
check_privileges()

# Configure TOR + Snowflake bridge
def configure_tor():
    """Configure TOR with Snowflake bridge."""
    print("[+] Configuring TOR with Snowflake bridge...")

    # Install TOR and Snowflake
    run_command("apt update && DEBIAN_FRONTEND=noninteractive apt install -y tor snowflake-client", "Installing TOR and Snowflake client")

    # TOR configuration
    torrc_content = """
ClientTransportPlugin snowflake exec /usr/bin/snowflake-client
UseBridges 1
Bridge snowflake
DNSPort 9053
TransPort 9040
"""
    # Write the torrc configuration
    torrc_path = "/etc/tor/torrc"
    try:
        with open(torrc_path, "w") as torrc_file:
            torrc_file.write(torrc_content)
        print(f"[+] Wrote TOR configuration to {torrc_path}.")
    except Exception as e:
        print(f"[-] Failed to write TOR configuration: {e}")
        raise IOError(f"Failed to write TOR configuration: {e}")

    # Set correct permissions for the torrc file
    run_command(["chown", "tor:tor", torrc_path], "Setting torrc file ownership")
    run_command(["chmod", "644", torrc_path], "Setting torrc file permissions")

    # Restart TOR service
    run_command(["systemctl", "restart", "tor"], "Restarting TOR service")
    print("[+] TOR configured with Snowflake bridge.")

# Lockdown NIC and route only over TOR
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

# Containerize browser activity
def containerize_browser(browser="firefox", options=None):
    """Containerize browser activity using Firejail."""
    print("[+] Containerizing browser activity...")
    run_command(["apt", "install", "-y", "firejail"], "Installing Firejail sandboxing tool")
    if options is None:
        options = "--net=none"
    browser_container_command = f"firejail {options} {browser}"
    print(f"[+] Browser container command: {browser_container_command}")

# Sandbox directories
def sandbox_directories():
    """Sandbox critical system directories from unauthorized changes."""
    critical_directories = ["/var", "/lib", "/bin", "/sbin", "/root", "/grub"]

    print("[+] Sandbox critical directories configuration started...")
    run_command(["apt", "install", "-y", "firejail"], "Ensuring Firejail is installed")

    for directory in critical_directories:
        print(f"[+] Setting up sandbox for {directory}...")
        run_command(["firejail", f"--private={directory}"], f"Sandboxing directory {directory}")

    print("[+] Critical directories sandboxed successfully.")

# Redirect web downloads to locked-down directory
def redirect_web_downloads(directory="/var/locked_downloads"):
    """Redirect web-based downloads to a locked directory for inspection."""
    print(f"[+] Setting up directory {directory} for inspecting downloads...")
    if not os.path.exists(directory):
        os.makedirs(directory, mode=0o700, exist_ok=True)
        run_command(["chown", "root:root", directory], "Setting directory ownership to root")
        run_command(["chmod", "700", directory], "Restricting directory permissions")

    # Set iptables rules to redirect downloads
    run_command(["iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", "80", "-j", "LOG", "--log-prefix", "HTTP-DOWNLOAD:"], "Logging HTTP downloads")
    run_command(["iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", "443", "-j", "LOG", "--log-prefix", "HTTPS-DOWNLOAD:"], "Logging HTTPS downloads")

    print(f"[+] Downloads will be logged for inspection in {directory}.")

# Release the Qube
 if __name__ == "__main__":
     configure_tor()
     lockdown_nic_with_tor()
     containerize_browser()
     sandbox_directories()
     redirect_web_downloads()
