#!/bin/bash


if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root!"
  exit 1
fi


VENV_DIR="/path/to/your/venv"
REQUIREMENTS_FILE="/path/to/requirements.txt"
RUN_MONITORS_SCRIPT="/path/to/run_monitors.py"
KILL_VERIFY_SCRIPT="/path/to/kill_VeriFY.py"
KILL_CRACK_SCRIPT="/path/to/kill_crack.py"
CRON_LOG="/path/to/install_dependencies.log"
INSTALL_DEPENDENCIES_SCRIPT="/path/to/install_dependencies.sh"


install_packages() {
  if [ -f /etc/debian_version ]; then
    # Debian-based OS
    apt-get update
    apt-get install -y python3 python3-venv python3-pip
  elif [ -f /etc/redhat-release ]; then
    # RHEL-based OS
    yum update -y
    yum install -y python3 python3-venv python3-pip
  else
    echo "Unsupported OS"
    exit 1
  fi
}





install_packages


if [ ! -d "$VENV_DIR" ]; then
  python3 -m venv $VENV_DIR
fi

source $VENV_DIR/bin/activate






pip install -r $REQUIREMENTS_FILE


cat <<EOL > $RUN_MONITORS_SCRIPT
import subprocess
import os
import sys

def check_root():
    if os.geteuid() != 0:
        print("This script must be run as root!")
        sys.exit(1)

def run_script(script_name):
    subprocess.Popen(['python3', script_name])

if __name__ == "__main__":
    check_root()
    
    kill_verify_script = '$KILL_VERIFY_SCRIPT'
    kill_crack_script = '$KILL_CRACK_SCRIPT'

    run_script(kill_verify_script)
    run_script(kill_crack_script)

    print("Both kill_VeriFY.py and kill_crack.py are running in the background.")
EOL


cat <<EOL > $INSTALL_DEPENDENCIES_SCRIPT
#!/bin/bash

source $VENV_DIR/bin/activate
pip install -r $REQUIREMENTS_FILE
python3 $RUN_MONITORS_SCRIPT
EOL

chmod +x $INSTALL_DEPENDENCIES_SCRIPT

# Setup cron job
(crontab -l ; echo "0 * * * * $INSTALL_DEPENDENCIES_SCRIPT >> $CRON_LOG 2>&1") | crontab -

# Run the install dependencies script initially to start the monitors
$INSTALL_DEPENDENCIES_SCRIPT

echo "Setup complete. Cron job has been configured to run the monitors every hour."
