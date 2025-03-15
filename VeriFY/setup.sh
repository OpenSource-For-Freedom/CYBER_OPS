# Setup file to get the tools needed in your eve


#!/bin/bash

# ROOT
if [ "$(id -u)" != "0" ]; then
  echo "This script must be run as root" 1>&2
  exit 1
fi

# UPDATE
apt update && apt upgrade -y

# INSTALL
apt install -y python3 python3-pip

# NMAP
apt install -y nmap

# PY
pip3 install python-nmap dpkt pythonping

# TKINTER
apt install -y python3-tk

# + as needed 
apt install -y gcc

echo "Setup completed successfully."
