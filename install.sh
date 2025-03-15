#!/bin/bash
#
# WordPress Stack Installer Bootstrap
# This is a very minimal script that downloads the main installer and runs it
#

# Download the main installer script to a temporary file
TMP_FILE=$(mktemp)
curl -sSL https://raw.githubusercontent.com/parhamfa/wordpress-stack-installer/main/wordpress-stack-setup.sh > "$TMP_FILE"

# Make it executable
chmod +x "$TMP_FILE"

# If not running as root, use sudo
if [[ $EUID -ne 0 ]]; then
    echo "This installer requires root privileges. Using sudo..."
    sudo bash "$TMP_FILE"
else
    # Run the installer script directly (not through a pipe)
    bash "$TMP_FILE"
fi

# Clean up
rm -f "$TMP_FILE"
