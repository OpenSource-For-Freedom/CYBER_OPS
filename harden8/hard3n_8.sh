#!/bin/bash
## Script to harden a Debian-based Linux build with minimum security enforcements

## Script options: e (exit on error), u (unset variable error), o (pipefail)
set -euo pipefail

## Function Definitions

## Logging configurations
LOG_DIR="/var/log/security_scans"
DATE=$(date +"%Y%m%d_%H%M%S")
SCRIPT_LOG="$LOG_DIR/script_execution_$DATE.log"

## Logging function
log() {
    echo "$(date +"%Y-%m-%d %T") $1" | sudo tee -a "$SCRIPT_LOG"
}

## Check if script runs as root
if [ "$(id -u)" -ne 0 ]; then
    log "Error: Please re-run this script with sudo or as root."
    exit 1
fi

## Command success check function
check_success() {
    if [ $? -ne 0 ]; then
        log "Error: $1 failed. Exiting script."
        exit 1
    else
        log "$1 completed successfully."
    fi
}

## Execute and log commands
exec_e() {
    log "Running: $*"
    "$@"
    check_success "$1"
}

## Check if a package is installed
is_package_installed() {
    dpkg -l "$1" | grep -q "^ii"
}

## Ensure the log directory exists
mkdir -p "$LOG_DIR"

## Script start log entry
echo "Starting hard3n_8.sh execution at $(date)" | sudo tee -a "$SCRIPT_LOG"

## Kernel hardening

## Copy custom grub configurations without overwriting existing values
exec_e cp -Rv ./etc/default/grub.d/* /etc/default/grub.d

## Update grub configuration
if command -v update-grub &>/dev/null; then
    exec_e update-grub
else
    exec_e grub-mkconfig -o /boot/grub/grub.cfg
fi

## Notify user about impending restart
echo 'Your system will restart in 10 seconds. Press Ctrl+C to cancel.'
sleep 10

## System reboot
exec_e reboot

## APT sandboxing options
echo 'APT::Sandbox::Seccomp "true";' | sudo tee /etc/apt/apt.conf.d/01seccomp
echo -e 'APT::AutoRemove::RecommendsImportant "false";\nAPT::Install-Recommends "0";\nAPT::Install-Suggests "0";' | sudo tee /etc/apt/apt.conf.d/01defaultrec

## Update package list
exec_e apt update

## Install and configure UFW if not installed
if ! is_package_installed ufw; then
    exec_e apt install -yy ufw --no-install-recommends --no-install-suggests
    exec_e ufw enable
    exec_e ufw default deny incoming
    exec_e systemctl --force --now enable ufw
    exec_e ufw reload
fi

## Install security packages
PACKAGES=("clamav" "rkhunter" "chkrootkit" "fail2ban" "lynis" "aide" "apparmor" "apparmor-profiles" "apparmor-profiles-extra" "apparmor-utils")
for package in "${PACKAGES[@]}"; do
    if ! is_package_installed "$package"; then
        exec_e apt install -yy "$package" --no-install-recommends --no-install-suggests
    fi
done

log "Security tools installed successfully."

## Source additional hardening script if it exists
if [[ -f harden8_deep.sh ]]; then
    source harden8_deep.sh
    if [ $? -eq 0 ]; then
        log "harden8_deep.sh executed successfully."
    else
        log "Error: harden8_deep.sh did not run successfully."
        exit 1
    fi
else
    log "Error: harden8_deep.sh not found. Skipping."
fi

## Run security scans
exec_e clamscan -r / --log="$LOG_DIR/clamav_scan_$DATE.log"
exec_e rkhunter --cronjob --update --quiet
exec_e chkrootkit | sudo tee "$LOG_DIR/chkrootkit_scan_$DATE.log"

log "Daily security scans completed. Logs stored in $LOG_DIR"
