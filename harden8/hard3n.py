#!/bin/bash

# Print the ASCII art and text
echo "        -----------------------------------------------------------------------"
echo "                    H   H   AAAAA   RRRR    DDDD    333333    NN    N"
echo "          ======== H   H  A     A  R   R   D   D       33    N N   N" ('=======')
echo "          ======= HHHHH  AAAAAAA  RRRR    D   D     33      N  N  N" ('========')
echo "          ====== H   H  A     A  R  R    D   D       33    N   N N" ('=========')
echo "                H   H  A     A  R   R   DDDD    333333    N    NN"
echo "        -----------------------------------------------------------------------"
echo "                    \"HARD3N\" - The Linux Security Project"
echo "                    ----------------------------------------"
echo "                     A project focused on improving Linux"
echo "                    security by automating, containerizing"
echo "                                Hardening and"
echo "                         System protection measures."
echo "                             License: MIT License"
echo "                                Version: 1.2"
echo "                               Dev: Tim + Kiu"
echo "          GitHub: https://github.com/OpenSource-For-Freedom/Linux.git"
echo ""
echo ""
echo ""

#  enable known mitigations for CPU vulnerabilities @kiu :) + @whonix
enable_cpu_mitigations() {
    echo "Enabling known mitigations for CPU vulnerabilities..."

    # Backup the existing GRUB configuration file
    sudo cp /etc/default/grub /etc/default/grub.bak

    # Add CPU mitigations to GRUB_CMDLINE_LINUX
    sudo sed -i 's/GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="mitigations=auto spectre_v2=on spec_store_bypass_disable=on l1tf=full,force mds=full tsx=off tsx_async_abort=full kvm.nx_huge_pages=force l1d_flush=on mmio_stale_data=full retbleed=auto /' /etc/default/grub

    # Update GRUB
    sudo update-grub
    echo "CPU mitigations enabled and GRUB configuration updated."
}

# Ensure the script is executed with root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: Please run this script as root or using sudo."
    exit 1
fi

# Enable CPU mitigations
enable_cpu_mitigations

# Additional security hardening actions
echo "Starting system hardening..."

# Log spec file directory
LOG_DIR="/var/log/security_scans"
sudo mkdir -p "$LOG_DIR"
DATE=$(date +"%Y%m%d_%H%M%S")
SCRIPT_LOG="$LOG_DIR/script_execution_$DATE.log"

echo "Starting system hard3ning at $(date)" | sudo tee -a "$SCRIPT_LOG"

# check if a package is installed (simpler)
is_package_installed() {
    dpkg -l "$1" | grep -q "^ii"
}

# log messages
log() {
    echo "$(date +"%Y-%m-%d %T") $1" | sudo tee -a "$SCRIPT_LOG"
}

# Verify if script is executed with root privileges
if [ "$(id -u)" -ne 0 ]; then
    log "Error: Please re-run this script with sudo or as root."
    exit 1
fi

# check if a command executed successfully
check_success() {
    if [ $? -ne 0 ]; then
        log "Error: $1 failed. Exiting script."
        exit 1
    else
        log "$1 completed successfully."
    fi
}

# Exec extended, logging and checking command was successful
exec_e() {
    "$@"
    check_success "$1"
}

# Update system packages
echo "Updating SEC_system packages..."
exec_e apt update && exec_e apt upgrade -yy

# Install security tools (Podman, LXC, Firejail, yeet:))
echo "Installing security tools..."
exec_e apt install -yy \
    podman \
    firejail \
    bubblewrap \
    ufw \
    fail2ban \
    clamav \
    lynis \
    apparmor apparmor-utils

# Check if Snap is installed
if ! command -v snap &> /dev/null; then
    log "SNAP not found. Installing Snap..."
    exec_e sudo apt update
    exec_e sudo apt install -y snapd
fi

# Check if LXD is installed
if ! command -v lxd &> /dev/null; then
    log "LXD not found. Installing LXD via Snap..."
    exec_e sudo snap install lxd
fi

# Optional: If you still want to add the PPA (for apt-based installation):
if ! command -v lxd &> /dev/null; then
    log "Adding LXD PPA..."
    exec_e sudo apt install -y software-properties-common
    exec_e sudo add-apt-repository ppa:ubuntu-lxc/lxd-stable
    exec_e sudo apt update
    exec_e sudo apt install -y lxd
fi

# Enable AppArmor
echo "Enabling AppArmor..."
exec_e sudo systemctl enable --now apparmor

# Enable UFW (Uncomplicated Firewall but no specific ports)
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

# Fail2Ban
echo "Enabling Fail2Ban..."
exec_e sudo systemctl enable --now fail2ban

# ClamAV
echo "Setting up ClamAV..."
exec_e sudo freshclam
exec_e sudo clamscan -r / --log="$LOG_DIR/clamav_scan_$DATE.log"

# Lynis
echo "Running Lynis system audit..."
exec_e sudo lynis audit system | tee "$LOG_DIR/lynis_audit_$DATE.log"

# Podman 
echo "Setting up Podman for Firefox container..."
if ! is_package_installed podman; then
    echo "Podman not installed, installing..."
    exec_e sudo apt install -yy podman
fi

# Pull Firefox container image
echo "Pulling Firefox container image..."
exec_e sudo podman pull jess/firefox

# Run Firefox in a container with network isolation (test)
echo "Running Firefox in a container (network isolation)..."
exec_e sudo podman run -it --rm --net=none jess/firefox

# LXC/LXD containerization 
echo "Setting up LXC/LXD containers..."
if ! is_package_installed lxd; then
    echo "LXD not installed, installing..."
    exec_e sudo apt install -yy lxd lxd-client
    exec_e sudo lxd init --auto
fi

# Create an LXC container for Firefox 
echo "Creating LXC container for Firefox..."
exec_e sudo lxc launch ubuntu:20.04 firefox-container
exec_e sudo lxc exec firefox-container -- apt update && sudo apt install -yy firefox
exec_e sudo lxc exec firefox-container -- firefox

# Firejail sandboxing for applications 
echo "Setting up Firejail sandbox for Firefox..."
exec_e firejail firefox

# Bubblewrap firefox only
echo "Setting up Bubblewrap for Firefox..."
exec_e bwrap --ro-bind / / --dev /dev --proc /proc --unshare-all --bind /home/$USER/.mozilla /home/$USER/.mozilla --bind /tmp /tmp -- /usr/bin/firefox

# Final Notification and Reboot
log "System hardening complete. All security measures are now in place."

# Prompt to reboot
read -p "MUST reboot to apply HARD3N8 updates and changes? (y/n): " REBOOT_NOW
if [[ "$REBOOT_NOW" == "y" ]]; then
    exec_e sudo reboot
else
    echo "Reboot the system to ensure all packages, files, and containerization can take full effect."
fi
