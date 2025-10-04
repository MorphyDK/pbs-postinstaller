#!/bin/bash
# Safe PBS Post-Install Script with iSCSI Setup and GitHub Post-Installer
set -e

GREEN="\e[32m"
RESET="\e[0m"
NEED_REBOOT=0

# --- Ensure root ---
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root" >&2
    exit 1
fi

echo -e ">>> Detecting Debian codename..."
OS_CODENAME=$(grep VERSION_CODENAME /etc/os-release | cut -d'=' -f2)
if [ -z "$OS_CODENAME" ]; then
    OS_CODENAME=$(lsb_release -cs 2>/dev/null || echo "bullseye")
fi
echo -e "Detected codename: ${GREEN}$OS_CODENAME${RESET}"

# --- Remove enterprise repos ---
read -e -p "$(echo -e "${GREEN}Disable enterprise updates and enable no-subscription repo? (y/N): ${RESET}")" disable_enterprise
if [[ "$disable_enterprise" =~ ^[Yy]$ ]]; then
    echo ">>> Removing all PBS enterprise repo files..."
    for FILE in /etc/apt/sources.list.d/pbs-enterprise*; do
        [ -e "$FILE" ] || continue
        rm -f "$FILE" && echo "Removed: $FILE"
    done

    echo ">>> Adding PBS no-subscription repo..."
    cat <<EOF > /etc/apt/sources.list.d/pbs-no-subscription.list
deb http://download.proxmox.com/debian/pbs $OS_CODENAME pbs-no-subscription
EOF

    echo ">>> Updating APT repositories..."
    apt update
else
    echo ">>> Skipping repo changes."
fi

# --- Optional upgrade ---
read -e -p "$(echo -e "${GREEN}Do you want to auto-upgrade packages? (y/N): ${RESET}")" do_upgrade
if [[ "$do_upgrade" =~ ^[Yy]$ ]]; then
    echo ">>> Upgrading packages..."
    apt upgrade -y
    NEED_REBOOT=1
else
    echo ">>> Skipping upgrade."
fi

# --- Optional iSCSI setup ---
read -e -p "$(echo -e "${GREEN}Do you want to install and configure iSCSI? (y/N): ${RESET}")" do_iscsi
if [[ "$do_iscsi" =~ ^[Yy]$ ]]; then
    echo ">>> Installing iSCSI packages..."
    apt install -y open-iscsi parted

    echo ">>> Loading iSCSI kernel modules..."
    modprobe iscsi_tcp
    modprobe scsi_transport_iscsi

    echo ">>> Verifying module load..."
    lsmod | grep iscsi_tcp || echo "iscsi_tcp module not loaded!"
    modinfo iscsi_tcp >/dev/null 2>&1 || echo "No iscsi_tcp module info found."

    echo ">>> Ensuring modules load on boot..."
    grep -qxF "iscsi_tcp" /etc/modules || echo "iscsi_tcp" >> /etc/modules
    grep -qxF "scsi_transport_iscsi" /etc/modules || echo "scsi_transport_iscsi" >> /etc/modules

    echo ">>> Configuring iscsid to start automatically..."
    sed -i 's/^node.startup = manual/node.startup = automatic/' /etc/iscsi/iscsid.conf

    echo ">>> Enabling and starting iSCSI services..."
    systemctl enable --now open-iscsi iscsid

    NEED_REBOOT=1
    echo ">>> iSCSI setup completed!"
else
    echo ">>> Skipping iSCSI setup."
fi

# --- Run the iSCSI mounting script from GitHub ---
GITHUB_SCRIPT_URL="https://raw.githubusercontent.com/MorphyDK/pbs-postinstaller/main/iSCSI_mounting.sh"
echo ">>> Downloading and running the iSCSI mounting script from GitHub..."
wget -O /tmp/iSCSI_mounting.sh "$GITHUB_SCRIPT_URL"
chmod +x /tmp/iSCSI_mounting.sh
/tmp/iSCSI_mounting.sh
echo ">>> GitHub iSCSI mounting script executed successfully!"
NEED_REBOOT=1  # assume the script might require a reboot

# --- Final reboot prompt at the end ---
if [[ $NEED_REBOOT -eq 1 ]]; then
    read -e -p "$(echo -e "${GREEN}Reboot is required to apply all changes. Reboot now? (y/N): ${RESET}")" confirm_reboot
    if [[ "$confirm_reboot" =~ ^[Yy]$ ]]; then
        echo ">>> Rebooting server..."
        reboot
    else
        echo ">>> Reboot skipped. Remember to reboot later to apply changes."
    fi
fi

echo ">>> PBS post-install script completed safely!"
