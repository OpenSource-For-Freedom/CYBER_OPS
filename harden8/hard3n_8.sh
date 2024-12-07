#!/bin/bash

## e, errexit | u, nounset (treats unset variables as errors, ensuring better uniformity)
## -o pipefail, ensures that if a command in a pipeline fails, the overall exit status of the pipeline is the status of the last command to fail, rather than just the status of the last command
set -euo pipefail

## Log spec file directory
LOG_DIR="/var/log/security_scans"
sudo mkdir -p "$LOG_DIR"
DATE=$(date +"%Y%m%d_%H%M%S")
SCRIPT_LOG="$LOG_DIR/script_execution_$DATE.log"

echo "Starting system hardening at $(date)" | sudo tee -a "$SCRIPT_LOG"

## Function to check if a package is installed (simpler)
is_package_installed() {
    dpkg -l "$1" | grep -q "^ii"
}

## Function to log messages
log() {
    echo "$(date +"%Y-%m-%d %T") $1" | sudo tee -a "$SCRIPT_LOG"
}

## Verify if script is executed with root privileges
if [ "$(id -u)" -ne 0 ]; then
    log "Error: Please re-run this script with sudo or as root."
    exit 1
fi

## Function to check if a command executed successfully
check_success() {
    if [ $? -ne 0 ]; then
        log "Error: $1 failed. Exiting script."
        exit 1
    else
        log "$1 completed successfully."
    fi
}

## Exec extended, logging and checking command was successful
exec_e() {
    "$@"
    check_success "$1"
}

## Update system packages
echo "Updating SEC_system packages..."
exec_e apt update && exec_e apt upgrade -yy

## Install security tools (Podman, LXC, Firejail, etc.)
echo "Installing security tools..."
exec_e apt install -yy \
    podman \
    lxd lxd-client \
    firejail \
    bubblewrap \
    ufw \
    fail2ban \
    clamav \
    lynis \
    apparmor apparmor-utils

## Enable AppArmor
echo "Enabling AppArmor..."
exec_e sudo systemctl enable --now apparmor

## Enable UFW (Uncomplicated Firewall but no specific ports)
echo "Setting up UFW firewall..."
exec_e sudo ufw enable
exec_e sudo ufw default deny incoming
exec_e sudo ufw default allow outgoing

# Ask user if SSH is needed and on what port
read -p "Do you need SSH access? (y/n): " SSH_NEEDED
if [[ "$SSH_NEEDED" == "y" ]]; then
    read -p "Enter inbound port for SSH (default 22): " SSH_PORT
    SSH_PORT=${SSH_PORT:-22}  # Default to port 22 if not specified
    read -p "Enter outbound port for SSH (default 22): " SSH_OUT_PORT
    SSH_OUT_PORT=${SSH_OUT_PORT:-22}  # Default to port 22 if not specified
    echo "Allowing SSH inbound and outbound on port $SSH_PORT and $SSH_OUT_PORT"
    exec_e sudo ufw allow "$SSH_PORT"
    exec_e sudo ufw allow out "$SSH_OUT_PORT"
else
    echo "SSH access is disabled."
fi

## Fail2Ban
echo "Enabling Fail2Ban..."
exec_e sudo systemctl enable --now fail2ban

## ClamAV
echo "Setting up ClamAV..."
exec_e sudo freshclam
exec_e sudo clamscan -r / --log="$LOG_DIR/clamav_scan_$DATE.log"

## Lynis
echo "Running Lynis system audit..."
exec_e sudo lynis audit system | tee "$LOG_DIR/lynis_audit_$DATE.log"

## Podman 
echo "Setting up Podman for Firefox container..."
if ! is_package_installed podman; then
    echo "Podman not installed, installing..."
    exec_e sudo apt install -yy podman
fi

# Pull Firefox container image
echo "Pulling Firefox container image..."
exec_e sudo podman pull jess/firefox

# Run Firefox in a container with network isolation (trial, would say we need to containerize any web-based search engine if it's downloaded after the fact)
echo "Running Firefox in a container (network isolation)..."
exec_e sudo podman run -it --rm --net=none jess/firefox

## LXC/LXD containerization (System containers all)
echo "Setting up LXC/LXD containers..."
if ! is_package_installed lxd; then
    echo "LXD not installed, installing..."
    exec_e sudo apt install -yy lxd lxd-client
    exec_e sudo lxd init --auto
fi

# Create an LXC container for Firefox (need to make this default for any search engine)
echo "Creating LXC container for Firefox..."
exec_e sudo lxc launch ubuntu:20.04 firefox-container
exec_e sudo lxc exec firefox-container -- apt update && sudo apt install -yy firefox
exec_e sudo lxc exec firefox-container -- firefox

## Firejail sandboxing for applications (Firefox example but make this default for any post downloaded search engine)
echo "Setting up Firejail sandbox for Firefox..."
exec_e firejail firefox

## Bubblewrap sandboxing (Firefox example and add for default search engines)
echo "Setting up Bubblewrap for Firefox..."
exec_e bwrap --ro-bind / / --dev /dev --proc /proc --unshare-all --bind /home/$USER/.mozilla /home/$USER/.mozilla --bind /tmp /tmp -- /usr/bin/firefox

## Final Notification and Reboot
log "System hardening complete. All security measures are now in place."

# Prompt user to reboot
read -p "MUST reboot to apply HARD3N8 updates and changes? (y/n): " REBOOT_NOW
if [[ "$REBOOT_NOW" == "y" ]]; then
    exec_e sudo reboot
else
    echo "Reboot the system to ensure all packages, files, and containerization can take full effect."
fi

