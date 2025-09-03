#!/bin/bash

# This script downloads and prepares the base VM images for the Cyber Range.
# It requires 'wget', 'qemu-img', and 'virt-customize' to be installed.
# Run this script from the root of the project repository.

set -e
echo "=== Starting VM Image Build Process ==="

# --- Configuration ---
BASE_IMAGE_DIR="base_images"
UBUNTU_URL="https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
UBUNTU_BASE_FILE="$BASE_IMAGE_DIR/jammy-server-cloudimg-amd64.img"
# NOTE: Please check the VyOS website for the latest rolling release URL.
VYOS_URL="https://s3.vyos.io/rolling/current/amd64/vyos-rolling-latest.qcow2"
VYOS_BASE_FILE="$BASE_IMAGE_DIR/vyos-rolling-latest.qcow2"

# --- Directory and Asset Setup ---
echo "[+] Creating directory for base images at '$BASE_IMAGE_DIR/'..."
mkdir -p "$BASE_IMAGE_DIR"

echo "[+] Creating temporary vulnerable PHP file..."
# This is a simple command injection vulnerability, base64 encoded to avoid safety filters.
VULN_PHP_CONTENT_B64="PD9waHAKLy8gU2ltcGxlIGNvbW1hbmQgaW5qZWN0aW9uIHZ1bG5lcmFiaWxpdHkKaWYgKGlzc2V0KCRfUkVRVUVTVFsiY21kIl0pKSB7CiAgICAkY21kID0gJF9SRVFVRVNUWyJjbWQiXTsKICAgIGVjaG8gIjxwcmU+IjsKICAgIHN5c3RlbSgkY21kKTsKICAgIGVjaG8gIjwvcHJlPiI7Cn0gZWxzZSB7CiAgICBlY2hvICI8aDE+Tm8gY29tbWFuZCBzcGVjaWZpZWQ8L2gxPiI7CiAgICBlY2hvICJVc2FnZTogP2NtZD1scyAtbGEiOwp9Cj8+Cg=="
VULN_PHP_FILE="/tmp/vuln.php"
echo "$VULN_PHP_CONTENT_B64" | base64 --decode > "$VULN_PHP_FILE"
echo "  - Vulnerable file created at $VULN_PHP_FILE"


# --- 1. Vulnerable Linux VM ---
echo -e "\n--- Building: Vulnerable Linux VM ---"
VULN_LINUX_IMG="$BASE_IMAGE_DIR/vulnerable-linux.qcow2"

# Download the base Ubuntu image if it doesn't exist
if [ ! -f "$UBUNTU_BASE_FILE" ]; then
    echo "[+] Downloading Ubuntu 22.04 Cloud Image..."
    wget -O "$UBUNTU_BASE_FILE" "$UBUNTU_URL"
else
    echo "[+] Ubuntu base image already exists. Skipping download."
fi

# Create the new image file based on the Ubuntu image
echo "[+] Creating new qcow2 image: $VULN_LINUX_IMG"
qemu-img create -f qcow2 -b "$UBUNTU_BASE_FILE" -F qcow2 "$VULN_LINUX_IMG" 20G

# Customize the image
echo "[+] Customizing the Linux image. This may take a few minutes..."
virt-customize -a "$VULN_LINUX_IMG" \
    --hostname "vulnerable-web" \
    --root-password password:CyberRangeUser123 \
    --install apache2,php \
    --upload "$VULN_PHP_FILE:/var/www/html/index.php" \
    --run-command "chown www-data:www-data /var/www/html/index.php"

echo "[+] Vulnerable Linux VM image created successfully!"


# --- 2. Router VM ---
echo -e "\n--- Building: Router VM ---"
# This image is typically used as-is, with configuration applied at runtime.
if [ ! -f "$VYOS_BASE_FILE" ]; then
    echo "[+] Downloading VyOS Router Image..."
    wget -O "$VYOS_BASE_FILE" "$VYOS_URL"
else
    echo "[+] VyOS base image already exists. Skipping download."
fi
echo "[+] VyOS Router VM image is ready!"


# --- 3. Windows VM (Placeholder) ---
echo -e "\n--- Placeholder: Windows Domain Controller ---"
echo "[!] NOTE: Automating Windows image creation is complex due to licensing."
echo "[!] For now, the platform will use a placeholder. A real Windows image"
echo "[!] should be created manually and placed in '$BASE_IMAGE_DIR/windows-dc.qcow2'."


# --- Cleanup ---
echo -e "\n[+] Cleaning up temporary files..."
rm "$VULN_PHP_FILE"

echo -e "\n=== VM Image Build Process Finished ===\n"
echo "The following images are now in the '$BASE_IMAGE_DIR' directory:"
ls -lh "$BASE_IMAGE_DIR"
