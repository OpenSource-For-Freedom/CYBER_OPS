# HARDN System
[Images/github-header-image.png]

## Mission
HARDN is a security toolkit designed to enhance system protection through a combination of lockdown measures, network anonymization via Tor, and file security features. Its goal is to make your system more secure, anonymous, and resistant to threats.

---

## Files Overview

### `hardn.py`
The core script of the HARDN system. It coordinates between the modules and acts as the main entry point for system lockdown and security operations.

### `hardn_tk.py`
A Tkinter-based GUI that allows users to interact with the system and choose between different security features like **Hardn Qubes** and **Dark Files**.

### `hardn_dark.py`
The file security module (planned). It will handle encrypted storage and secure access for critical files.

### `hardn_qubes.py`
Handles the core lockdown process, including:
- Routing network traffic through Tor.
- Containerizing browser activity with Firejail.
- Locking down network interfaces (NIC).
- Creating sandboxed directories for system protection.

---

## Setup

### Prerequisites
- **Debian-based OS** (Debian/Ubuntu recommended)
- **Python 3.x**
- Install dependencies:

  ```bash
  sudo apt update
  sudo apt install -y python3 python3-pip tor firejail
  pip3 install pillow
  
  ## How It Works

- **hardn.py**: Runs the main functionality, initiating security processes based on user input.
- **hardn_tk.py**: GUI interface for selecting between available options and executing security actions.
- **hardn_dark.py**: (Coming soon) Handles file security features like encryption.
- **hardn_qubes.py**: Enforces strict network lockdown, routes all traffic through Tor and verifies browser control for downloads. 

---

## Troubleshooting

If you encounter issues with Tor not starting, try restarting the Tor service:

```bash
sudo systemctl restart tor

flush the network rules

sudo iptables -F
sudo iptables -t nat -F
