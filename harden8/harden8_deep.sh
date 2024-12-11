#!/bin/bash
LOG_FILE="/var/log/hard3n_deep.log"

log() {
    echo "$(date +"%Y-%m-%d %H:%M:%S") $1" | tee -a "$LOG_FILE"
}

run_command() {
    "$@" || { log "[-] Error: Command '$*' failed."; exit 1; }
}

disable_core_dumps() {
    log "[+] Disabling core dumps..."
    run_command echo '* hard core 0;' | sudo tee -a /etc/security/limits.conf
}

configure_tcp_wrappers() {
    log "[+] Configuring TCP Wrappers..."
    echo "ALL: ALL" | sudo tee -a /etc/hosts.deny
}

restrict_non_local_logins() {
    log "[+] Restricting non-local logins..."
    echo "-:ALL:ALL EXCEPT LOCAL" | sudo tee -a /etc/security/access.conf
}

secure_files() {
    log "[+] Securing configuration files..."
    sudo chmod 600 /etc/security/limits.conf
    sudo chmod 600 /etc/hosts.deny
    sudo chmod 600 /etc/security/access.conf
}

main() {
    disable_core_dumps
    configure_tcp_wrappers
    restrict_non_local_logins
    secure_files
    log "[+] hard3n_deep.sh completed successfully."
}

main