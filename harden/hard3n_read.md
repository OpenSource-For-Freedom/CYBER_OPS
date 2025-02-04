# HARD3N System

## Mission
HARD3N is a security toolkit designed to enhance system protection through a combination of lockdown measures, network anonymization via Tor, and file security features. Its goal is to make your system more secure, anonymous, and resistant to threats.

---

## Files Overview

### `hard3n.py`
The core script of the HARD3N system. It coordinates between the modules and acts as the main entry point for system lockdown and security operations.

### `hard3n_tk.py`
A Tkinter-based GUI that allows users to interact with the system and choose between different security features like **Hard3n Qubes** and **Dark Files**.

### `hard3n_dark.py`
The file security module (planned). It will handle encrypted storage and secure access for critical files.

### `hard3n_qubes.py`
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
  '''
  
  How It Works
	•	hard3n.py: Runs the main functionality, initiating security processes based on user input.
	•	hard3n_tk.py: GUI interface for selecting between available options and executing security actions.
	•	hard3n_dark.py: (Coming soon) Handles file security features like encryption.
	•	hard3n_qubes.py: Enforces strict network lockdown, routes all traffic through Tor, and uses Firejail for browser containerization.

Troubleshooting

### If you encounter issues with Tor not starting, try restarting the Tor service:
'''
### sudo systemctl restart tor
'''
### To flush any network lockdown rules (if internet access is lost):
'''
sudo iptables -F
sudo iptables -t nat -F
'''
> License

### MIT License

|Author|

>Tim Burns
>Security Engineer | Developer