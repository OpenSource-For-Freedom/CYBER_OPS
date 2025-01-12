#!/bin/bash

echo "Spinning Up hard3n package..."

# Install dependencies
if [ -f "requirements.txt" ]; then
  echo "Installing Python dependencies..."
  pip install -r requirements.txt
fi

# Set permissions
chmod +x hard3n.py hard3n_dark.py hard3n_qube.py hard3n.sh

# Copy config files to /etc 
if [ -d "etc" ]; then
  echo "Copying configuration files to /etc/hard3n..."
  sudo mkdir -p /etc/hard3n
  sudo cp -r etc/* /etc/hard3n/
fi

echo "Setup complete."