#!/bin/bash
# Install AppArmor on Rocky Linux 9.5

echo "Installing AppArmor on Rocky Linux..."

# Install AppArmor packages
dnf install -y apparmor apparmor-utils apparmor-profiles

# Enable AppArmor in GRUB
grubby --update-kernel=ALL --args="apparmor=1 security=apparmor"

echo "AppArmor installed. Reboot required to enable."
echo "After reboot, run: systemctl enable --now apparmor"