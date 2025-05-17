#!/usr/bin/env python3

# sudo python3 monitor.py

# runs as a service and alerts using dbus

import os
import subprocess
import threading
import shutil
import time
import getpass
import sys
import gi


LOG_KEYWORDS = ["ALERT", "WARNING", "UNAUTHORIZED", "ERROR"]
LOG_FILE = "/var/log/hardn/monitor.log"
SCRIPT_PATH = "/opt/hardn/monitors/run_monitors.sh"
SERVICE_NAME = "monitor_gui.service"

BANNER = r"""
   ▄▄▄▄███▄▄▄▄    ▄██████▄  ███▄▄▄▄    ▄█      ███      ▄██████▄     ▄████████      
 ▄██▀▀▀███▀▀▀██▄ ███    ███ ███▀▀▀██▄ ███  ▀█████████▄ ███    ███   ███    ███      
 ███   ███   ███ ███    ███ ███   ███ ███▌    ▀███▀▀██ ███    ███   ███    ███      
 ███   ███   ███ ███    ███ ███   ███ ███▌     ███   ▀ ███    ███  ▄███▄▄▄▄██▀      
 ███   ███   ███ ███    ███ ███   ███ ███▌     ███     ███    ███ ▀▀███▀▀▀▀▀        
 ███   ███   ███ ███    ███ ███   ███ ███      ███     ███    ███ ▀███████████      
 ███   ███   ███ ███    ███ ███   ███ ███      ███     ███    ███   ███    ███      
  ▀█   ███   █▀   ▀██████▀   ▀█   █▀  █▀      ▄████▀    ▀██████▀    ███    ███      
                                                                    ███    ███      
"""


def install_dependencies():
    apt_packages = ["libnotify-bin", "python3-gi", "gir1.2-appindicator3-0.1"]
    pip_packages = ["notify2"]
    try:
        print("[+] Installing system dependencies...")
        subprocess.run(["sudo", "apt", "update"], check=True)
        subprocess.run(["sudo", "apt", "install", "-y"] + apt_packages, check=True)
    except Exception:
        print("[!] System-level dependency install failed or already done.")
    try:
        print("[+] Installing Python packages...")
        subprocess.run([sys.executable, "-m", "pip", "install"] + pip_packages, check=True)
    except Exception:
        print("[!] Python package install failed or already done.")


def run_monitor_script():
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "w") as log_file:
        subprocess.Popen(['bash', SCRIPT_PATH], stdout=log_file, stderr=log_file)


def monitor_logs():
    import notify2
    notify2.init("HARDN Monitor")
    last_pos = 0
    while True:
        if not os.path.exists(LOG_FILE):
            time.sleep(3)
            continue
        with open(LOG_FILE, "r") as f:
            f.seek(last_pos)
            new_lines = f.readlines()
            last_pos = f.tell()
        for line in new_lines:
            if any(k in line.upper() for k in LOG_KEYWORDS):
                n = notify2.Notification("HARDN Alert", line.strip())
                n.set_urgency(notify2.URGENCY_CRITICAL)
                n.show()
        time.sleep(3)


def build_menu(Gtk):
    menu = Gtk.Menu()
    quit_item = Gtk.MenuItem(label="Quit Monitor")
    quit_item.connect("activate", Gtk.main_quit)
    menu.append(quit_item)
    menu.show_all()
    return menu


def tray_main():
    install_dependencies()
    setup_user_service()

    from gi.repository import Gtk, AppIndicator3
    import notify2

    notify2.init("HARDN Monitor")

    indicator = AppIndicator3.Indicator.new(
        "hardn-tray",
        "network-transmit-receive",
        AppIndicator3.IndicatorCategory.APPLICATION_STATUS
    )
    indicator.set_status(AppIndicator3.IndicatorStatus.ACTIVE)
    indicator.set_menu(build_menu(Gtk))

    threading.Thread(target=run_monitor_script, daemon=True).start()
    threading.Thread(target=monitor_logs, daemon=True).start()

    Gtk.main()


def setup_user_service():
    user_dir = os.path.expanduser("~/.config/systemd/user")
    os.makedirs(user_dir, exist_ok=True)
    service_path = os.path.join(user_dir, SERVICE_NAME)
    python_exec = shutil.which("python3")
    script_exec = os.path.realpath(__file__)

    if not os.path.exists(service_path):
        with open(service_path, "w") as f:
            f.write(f"""[Unit]
Description=HARDN Log Monitor GUI (User)
After=default.target

[Service]
ExecStart={python_exec} {script_exec}
Restart=on-failure
Environment=DISPLAY=:0
Environment=XAUTHORITY=$HOME/.Xauthority

[Install]
WantedBy=default.target
""")
        subprocess.run(["systemctl", "--user", "daemon-reload"])
        subprocess.run(["systemctl", "--user", "enable", SERVICE_NAME])
        print("[+] User systemd service created and enabled.")

# MAIN
if __name__ == "__main__":
    print(BANNER)
    tray_main()