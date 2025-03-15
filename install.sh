#!/bin/bash
#
# WordPress Stack Installer Bootstrap
# Author: Parham Fatemi
# Date: March 13, 2025
#

# Check if running with sudo
if [[ $EUID -ne 0 ]]; then
    echo "This installer must be run with sudo."
    echo "Please run: sudo curl -sSL https://raw.githubusercontent.com/parhamfa/wordpress-stack-installer/main/install.sh | bash"
    exit 1
fi

echo "WordPress Stack Installer"
echo "========================="
echo "Downloading installation script..."

# Create temporary file
TMP_FILE=$(mktemp -p /tmp wp-stack-XXXXXX.sh)

# Download the main script
curl -sSL https://raw.githubusercontent.com/parhamfa/wordpress-stack-installer/main/wordpress-stack-setup.sh -o "$TMP_FILE"

# Make it executable
chmod +x "$TMP_FILE"

echo "Starting installation..."
echo

# Run the script
"$TMP_FILE"

# Capture exit code
EXIT_CODE=$?

# Clean up
rm -f "$TMP_FILE"

exit $EXIT_CODE
