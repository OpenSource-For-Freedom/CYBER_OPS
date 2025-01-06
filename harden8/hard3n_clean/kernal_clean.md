# Here lies a stepped process for keeping your Linux System in tip top shape. 


# Debian-based Linux Maintenance Guide

This guide provides detailed steps to maintain your Debian-based system, ensuring it uses correct repository mirrors, has up-to-date packages, manages dependencies effectively, and cleans up unnecessary old kernel files.

## 1. Check and Set the Correct Repository Mirror

>Open the Sources List**: Access your `sources.list` file with a text editor using the command below:

  ```
  sudo nano /etc/apt/sources.list
  ```

>Verify or Change the Mirror**: Replace the mirror URLs with reliable sources. You can find a list of Debian mirrors [here](https://www.debian.org/mirror/list). Ensure the URLs correspond to your Debian version (e.g., `buster`, `bullseye`).

  ```
  deb http://deb.debian.org/debian buster main contrib non-free
  deb http://deb.debian.org/debian-security buster/updates main contrib non-free
  deb http://deb.debian.org/debian buster-updates main contrib non-free
  ```

>Save and Close**: After editing, save the file and exit the editor.

## 2. Update and Upgrade the System

Ensure your system is up-to-date with the latest package versions and security updates.

>Update Package Lists**:

  ```
  sudo apt update
  ```

>Upgrade Installed Packages**:

  ```
  sudo apt upgrade
  ```

>Perform a Full Upgrade**:

  ```
  sudo apt full-upgrade
  ```

## 3. Manage Dependencies and Clean Up

Remove unused packages and resolve any broken dependencies.

>Fix Broken Dependencies**:

  ``` 
  sudo apt -f install
  ```

>Auto-Remove Unnecessary Packages**:

  ```
  sudo apt autoremove
  ```

## 4. Remove Old Kernel Files

Old kernels can clutter your system. Keep it clean by removing outdated kernels, but be careful not to remove the currently active kernel.

>List Currently Installed Kernels**:

  ```
  dpkg --list 'linux-image*'
  ```

- **Check Which Kernel You're Currently Using**:

  ```
  uname -r
  ```

- **Remove Outdated Kernels** (replace `x.x.x-xx` with the actual version you wish to remove):

  ```
  sudo apt remove linux-image-x.x.x-xx-generic
  ```

- **Update GRUB**:

  ```
  sudo update-grub
  ```

## 5. Cleanup Old Package Archives

Keep your system storage lean by cleaning up old package files.

>Clean Package Archives**:

  ```
  sudo apt clean
  ```

## 6. Check System for Errors

Monitor your system for any errors that could indicate underlying issues.

>Check for System Errors**:

  ```
  journalctl -p err -b
  ```

## 7. Reboot Your System

It's good practice to reboot your system after significant updates, especially kernel updates, to ensure all changes are applied properly.

>Reboot the System**:

  ```
  sudo reboot
  ```
---
Please Follow these steps regularly to keep your Debian-based system in good health and performance, dont be lazy. 
