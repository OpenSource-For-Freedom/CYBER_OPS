#!/bin/bash
## Script to harden a Debian-based Linux build with minimum security enforcements.
# completly simplified version 2
set -euo pipefail

## Kernel level mitigations (to be expanded)
# Note: Update apparmor.cfg if present and ensure grub update was successful.

## Copy configurations without overwriting pre-existing values
sudo cp -Rv ./etc/default/grub.d/* /etc/default/grub.d

## Update grub configuration
if command -v update-grub &>/dev/null; then
    sudo update-grub
else
    sudo grub-mkconfig -o /boot/grub/grub.cfg
fi

## Notify and reboot system
echo 'Your system will restart in 10 seconds. Cancel with Ctrl+C if needed.'
sleep 10
sudo reboot

## Log directory
LOG_DIR="/var/log/security_scans"
sudo mkdir -p "$LOG_DIR"
DATE=$(date +"%Y%m%d_%H%M%S")
SCRIPT_LOG="$LOG_DIR/script_execution_$DATE.log"

## Logging function
log() {
    echo "$(date +"%Y-%m-%d %T") $1" | sudo tee -a "$SCRIPT_LOG"
}

## Verify root privileges
if [ "$(id -u)" -ne 0 ]; then
    log "Error: Please run as root."
    exit 1
fi

## Check command success
exec_e() {
    "$@" || { log "Error: $1 failed. Exiting."; exit 1; }
    log "$1 completed successfully."
}

## Reduce attack surface
echo 'APT::Sandbox::Seccomp "true";' | sudo tee /etc/apt/apt.conf.d/01seccomp
echo -e 'APT::AutoRemove::RecommendsImportant "false";\nAPT::Install-Recommends "0";\nAPT::Install-Suggests "0";' | sudo tee /etc/apt/apt.conf.d/01defaultrec

## Update package list
exec_e apt update

## Install security packages
PACKAGES=("ufw" "clamav" "rkhunter" "chkrootkit" "fail2ban" "lynis" "aide" "apparmor apparmor-profiles apparmor-profiles-extra apparmor-utils")
for package in "${PACKAGES[@]}"; do
    if ! dpkg -l "$package" | grep -q "^ii"; then
        exec_e apt install -yy $package --no-install-recommends --no-install-suggests
    fi
done

log "Security tools installed successfully."

## Enable UFW and configure
exec_e ufw enable
exec_e ufw default deny incoming
exec_e ufw default allow outgoing
exec_e systemctl enable --now ufw

## Run security scans
exec_e clamscan -r / --log="$LOG_DIR/clamav_scan_$DATE.log"
exec_e rkhunter --cronjob --update --quiet
exec_e chkrootkit | sudo tee "$LOG_DIR/chkrootkit_scan_$DATE.log"

log "Daily security scans completed. Logs stored in $LOG_DIR."

## Reboot the system
sudo reboot