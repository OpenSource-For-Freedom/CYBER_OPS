#!/bin/bash

echo "##############################################################"
echo "#       ██░ ██  ▄▄▄       ██▀███  ▓█████▄  ███▄    █         #"
echo "#      ▓██░ ██▒▒████▄    ▓██ ▒ ██▒▒██▀ ██▌ ██ ▀█   █         #"
echo "#      ▒██▀▀██░▒██  ▀█▄  ▓██ ░▄█ ▒░██   █▌▓██  ▀█ ██▒        #"
echo "#      ░▓█ ░██ ░██▄▄▄▄██ ▒██▀▀█▄  ░▓█▄   ▌▓██▒  ▐▌██▒        #"
echo "#      ░▓█▒░██▓ ▓█   ▓██▒░██▓ ▒██▒░▒████▓ ▒██░   ▓██░        #"
echo "#       ▒ ░░▒░▒ ▒▒   ▓▒█░░ ▒▓ ░▒▓░ ▒▒▓  ▒ ░ ▒░   ▒ ▒         #"
echo "#       ▒ ░▒░ ░  ▒   ▒▒ ░  ░▒ ░ ▒░ ░ ▒  ▒ ░ ░░   ░ ▒░        #"
echo "#       ░  ░░ ░  ░   ▒     ░░   ░  ░ ░  ░    ░   ░ ░         #"
echo "#       ░  ░  ░      ░  ░   ░        ░             ░         #"
echo "#                           ░                                #"
echo "#               THE LINUX SECURITY PROJECT                   #"
echo "#                                                            #"
echo "#                                                            #"      
echo "##############################################################"

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

echo "-------------------------------------------------------"
echo "                   HARDN - SETUP                       "
echo "-------------------------------------------------------"

# Ensure the script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root. Use: sudo ./setup.sh"
   exit 1
fi

cd "$(dirname "$0")"

echo "[+] Updating system packages..."
apt update && apt upgrade -y
sudo apt install -y build-essential python3-dev python3-setuptools python3-wheel cython3

echo "[+] Installing required system dependencies..."
apt install -y python3 python3-venv python3-pip ufw fail2ban apparmor apparmor-profiles apparmor-utils firejail tcpd lynis debsums build-essential python3-dev python3-setuptools python3-wheel libp[...]

echo "-------------------------------------------------------"
echo "                 BUILD PYTHON EVE                      "
echo "-------------------------------------------------------"

echo "[+] Setting up Python virtual environment..."
rm -rf setup/venv
python3 -m venv setup/venv
source setup/venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt

echo "[+] Installing HARDN as a system-wide command..."
pip install -e .
#!/bin/bash
files=("hardn_dark.py" "gui.py" "kernal.py")

for file in "${files[@]}"; do
    filepath=$(find / -name "$file" 2>/dev/null | head -n 1)
    if [ -n "$filepath" ]; then
        chmod +x "$filepath"
        echo "Executable permission added to $filepath"
    else
        echo "Warning: $file not found. Skipping chmod."
    fi
done

echo "-------------------------------------------------------"
echo "                     SECURITY                          "
echo "-------------------------------------------------------"

# Secure sensitive environment variables
export_sensitive_variables() {
  echo "Exporting sensitive environment variables..."
  set -o allexport
  # export DB_PASSWORD='your_password_here'
  # export API_KEY='your_api_key_here'
  set +o allexport
}

# Configure TCP Wrappers
configure_tcp_wrappers() {
  echo "Configuring TCP Wrappers..."
  echo "ALL: ALL" >> /etc/hosts.deny
  echo "sshd: ALL" >> /etc/hosts.allow
}

# Configure UFW
configure_ufw() {
  echo "Configuring UFW..."
  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow out to any port 1:65535 proto tcp
  ufw deny out to any proto udp
  ufw --force enable
}

# Disable core dumps
disable_core_dumps() {
  echo "Disabling core dumps..."
  echo "* hard core 0" >> /etc/security/limits.conf
  echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
  sysctl -p
}

# Disable unused filesystems
disable_unused_filesystems() {
  echo "Disabling unused filesystems..."
  CIS_FILE="/etc/modprobe.d/CIS.conf"
  FILESYSTEMS=("cramfs" "freevxfs" "jffs2" "hfs" "hfsplus" "squashfs" "udf")
  for fs in "${FILESYSTEMS[@]}"; do
    echo "install $fs /bin/true" >> "$CIS_FILE"
  done
}

# Setup auditd to monitor the virtual environment
setup_auditd_venv_monitoring() {
  echo "Setting up auditd to monitor virtual environment..."
  if [ -d "$VENV_PATH" ]; then
    echo "-w $VENV_PATH -p wa -k venv_audit" > /etc/audit/rules.d/venv.rules
    service auditd restart
  else
    echo "Warning: $VENV_PATH not found. Skipping auditd setup."
  fi
}

# Install security tools in the virtual environment
install_python_security_tools() {
  echo "Installing Bandit and Safety in virtual environment..."
  if [ -d "$VENV_PATH" ]; then
    source "$VENV_PATH/bin/activate"
    pip install --upgrade pip
    pip install bandit safety
    deactivate
  else
    echo "Virtual environment not found at $VENV_PATH. Skipping install."
  fi
}

# Run security scans
run_python_security_scans() {
  echo "Running Bandit and Safety scans..."
  mkdir -p "$LOG_DIR"
  BANDIT_LOG="$LOG_DIR/bandit.log"
  SAFETY_LOG="$LOG_DIR/safety.log"

  if [ -d "$VENV_PATH" ] && [ -d "$CODE_PATH" ]; then
    source "$VENV_PATH/bin/activate"
    bandit -r "$CODE_PATH" > "$BANDIT_LOG"
    safety check --full-report > "$SAFETY_LOG"
    deactivate
    echo "Logs saved to $LOG_DIR"
  else
    echo "Error: Missing VENV or CODE path. Skipping scans."
  fi
}

# Setup cron jobs for security scans
setup_security_scan_cronjobs() {
  echo "Setting up daily cron jobs for Bandit and Safety..."
  CRON_TEMP="/tmp/current_cron"
  crontab -l 2>/dev/null > "$CRON_TEMP"

  if ! grep -q "$VENV_PATH/bin/bandit" "$CRON_TEMP"; then
    echo "0 0 * * * $VENV_PATH/bin/bandit -r $CODE_PATH >> $LOG_DIR/bandit_cron.log 2>&1" >> "$CRON_TEMP"
  fi
  if ! grep -q "$VENV_PATH/bin/safety" "$CRON_TEMP"; then
    echo "0 1 * * * $VENV_PATH/bin/safety check --full-report >> $LOG_DIR/safety_cron.log 2>&1" >> "$CRON_TEMP"
  fi

  crontab "$CRON_TEMP"
  rm -f "$CRON_TEMP"
}

main() {
  export_sensitive_variables
  configure_tcp_wrappers
  configure_ufw
  disable_core_dumps
  disable_unused_filesystems
  setup_auditd_venv_monitoring
  install_python_security_tools
  run_python_security_scans
  setup_security_scan_cronjobs

  echo "System hardening and Python security setup complete."
}

main

echo "-------------------------------------------------------"
echo "                      THE PURGE                        "
echo "-------------------------------------------------------"

echo "[+] Checking for unnecessary packages to remove..."
if sudo apt autoremove --dry-run | grep -q "The following packages will be REMOVED"; then
    echo "[!] The following packages will be removed:"
    sudo apt autoremove --dry-run | grep "The following packages will be REMOVED" -A 10
    echo "[+] Proceeding with autoremove..."
    sudo apt autoremove -y
else
    echo "[+] No unnecessary packages to remove."
fi

echo "[+] Cleaning up package cache..."
sudo apt autoclean -y
sudo apt clean -y

echo "[+] Ensuring debsums is installed..."
if ! dpkg -l | grep -q debsums; then
	apt install -y debsums
fi

echo "[+] Running Debsums..."
debsums -a -s -c 2>&1 | tee /var/log/debsums.log

echo "-------------------------------------------------------"
echo "                          CRON                         "
echo "-------------------------------------------------------"

echo "[+] Checking for cron jobs..."
if [ -f /etc/cron.deny ]; then
    echo "[!] Removing /etc/cron.deny..."
    rm /etc/cron.deny
fi

(crontab -l 2>/dev/null; echo "* * * * * /path/to/Setup.sh >> /var/log/setup.log 2>&1") | crontab -

# Build cron for updates and security checks
echo "[+] Creating cron jobs..."
echo "0 0 * * * root apt update && apt upgrade -y" > /etc/cron.d/hardn
echo "0 0 * * * root lynis audit system" >> /etc/cron.d/hardn
echo "0 0 * * * root debsums -s" >> /etc/cron.d/hardn
echo "0 0 * * * root rkhunter --check" >> /etc/cron.d/hardn
echo "0 0 * * * root clamscan -r /" >> /etc/cron.d/hardn
echo "0 0 * * * root maldet -a /" >> /etc/cron.d/hardn
echo "0 0 * * * root chkrootkit" >> /etc/cron.d/hardn
echo "0 0 * * * root firejail --list" >> /etc/cron.d/hardn
echo "0 0 * * * root harden" >> /etc/cron.d/hardn

# Ensure cron jobs are set to run daily
echo "[+] Setting cron jobs to run daily..."
chmod 644 /etc/cron.d/hardn

# Print report of security findings on desktop
echo "[+] Creating daily security report..."
echo "lynis audit system" > /etc/cron.daily/hardn
echo "debsums -s" >> /etc/cron.daily/hardn
echo "rkhunter --check" >> /etc/cron.daily/hardn
echo "clamscan -r /" >> /etc/cron.daily/hardn
echo "maldet -a /" >> /etc/cron.daily/hardn
echo "chkrootkit" >> /etc/cron.daily/hardn
echo "firejail --list" >> /etc/cron.daily/hardn
echo "harden" >> /etc/cron.daily/hardn

# Make sure report is password protected by root user
echo "[+] Setting permissions on daily security report..."
chmod 700 /etc/cron.daily/hardn

echo "-------------------------------------------------------"
echo "[+]               HARDN SETUP COMPLETE"
echo "-------------------------------------------------------"