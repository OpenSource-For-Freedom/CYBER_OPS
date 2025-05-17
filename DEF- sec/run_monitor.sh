#!/bin/bash

# this is fhe monitor for COC
# to run as a servuce: sudo python3 monitor.py

#!/bin/bash

set -e

BASE_DIR="/opt/monitor_orchestrator"
VENV_DIR="$BASE_DIR/venv"
REQS="$BASE_DIR/requirements.txt"
RUNNER="$BASE_DIR/run_monitors.py"
DAEMON="$BASE_DIR/orchestrator_daemon.sh"
INSTALL_SCRIPT="$BASE_DIR/install_dependencies.sh"
WATCHDOG_SCRIPT="$BASE_DIR/watchdog.sh"
GLOBAL_LOG="$BASE_DIR/global_monitor.log"
WATCHDOG_LOG="$BASE_DIR/watchdog.log"

echo "[+] Creating base directory at $BASE_DIR"
mkdir -p "$BASE_DIR"

echo "[+] Installing Python if necessary..."
if [ -f /etc/debian_version ]; then
  apt-get update && apt-get install -y python3 python3-venv python3-pip
elif [ -f /etc/redhat-release ]; then
  yum update -y && yum install -y python3 python3-venv python3-pip
else
  echo "Unsupported OS."
  exit 1
fi

echo "[+] Setting up Python virtual environment..."
if [ ! -d "$VENV_DIR" ]; then
  python3 -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"

if [ -f "$REQS" ]; then
  pip install -r "$REQS"
else
  echo "requirements.txt not found. You can manually add it to $REQS later."
fi

echo "[+] Creating monitor launcher script..."
cat <<EOF > "$RUNNER"
import os
import subprocess
import sys

def check_root():
    if os.geteuid() != 0:
        print("This script must be run as root!")
        sys.exit(1)

def run_scripts(directory, global_log):
    for filename in os.listdir(directory):
        if filename.endswith(".py") and filename != "run_monitors.py":
            path = os.path.join(directory, filename)
            subprocess.Popen(
                ['python3', path],
                stdout=open(global_log, 'a'),
                stderr=subprocess.STDOUT
            )

if __name__ == "__main__":
    check_root()
    run_scripts("$BASE_DIR", "$GLOBAL_LOG")
    print("All monitor scripts launched and logging to $GLOBAL_LOG")
EOF

echo "[+] Creating daemon launch script..."
cat <<EOF > "$DAEMON"
#!/bin/bash
source "$VENV_DIR/bin/activate"
python3 "$RUNNER" >> "$GLOBAL_LOG" 2>&1
EOF
chmod +x "$DAEMON"

echo "[+] Creating install helper script..."
cat <<EOF > "$INSTALL_SCRIPT"
#!/bin/bash
source "$VENV_DIR/bin/activate"
[ -f "$REQS" ] && pip install -r "$REQS"
python3 "$RUNNER"
EOF
chmod +x "$INSTALL_SCRIPT"

echo "[+] Creating watchdog script..."
cat <<EOF > "$WATCHDOG_SCRIPT"
#!/bin/bash
SERVICE="monitor_orchestrator.service"
LOG="$WATCHDOG_LOG"

if ! systemctl is-active --quiet \$SERVICE; then
  echo "\$(date): \$SERVICE not active. Restarting..." >> \$LOG
  systemctl restart \$SERVICE
else
  echo "\$(date): \$SERVICE is running." >> \$LOG
fi
EOF
chmod +x "$WATCHDOG_SCRIPT"

echo "[+] Creating orchestrator service file..."
cat <<EOF > /etc/systemd/system/monitor_orchestrator.service
[Unit]
Description=Monitor Orchestrator Service
After=network.target

[Service]
Type=simple
ExecStart=$DAEMON
WorkingDirectory=$BASE_DIR
StandardOutput=append:$GLOBAL_LOG
StandardError=append:$GLOBAL_LOG
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

echo "[+] Creating watchdog service file..."
cat <<EOF > /etc/systemd/system/orchestrator_watchdog.service
[Unit]
Description=Orchestrator Watchdog Script

[Service]
Type=oneshot
ExecStart=$WATCHDOG_SCRIPT
EOF

echo "[+] Creating watchdog timer file..."
cat <<EOF > /etc/systemd/system/orchestrator_watchdog.timer
[Unit]
Description=Run Orchestrator Watchdog every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
Unit=orchestrator_watchdog.service

[Install]
WantedBy=timers.target
EOF

echo "[+] Reloading systemd and enabling services..."
systemctl daemon-reexec
systemctl daemon-reload
systemctl enable monitor_orchestrator.service
systemctl enable orchestrator_watchdog.timer

echo "[+] Starting services..."
systemctl start monitor_orchestrator.service
systemctl start orchestrator_watchdog.timer

echo "[✓] Setup complete. All scripts are running and monitored."
echo "    Logs: $GLOBAL_LOG"
echo "    Watchdog Log: $WATCHDOG_LOG"