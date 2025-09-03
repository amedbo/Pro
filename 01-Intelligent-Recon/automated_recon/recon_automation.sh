#!/bin/bash

# Simple Reconnaissance Automation Script

# --- Configuration ---
PROFILER_SCRIPT="01-Intelligent-Recon/automated_recon/target_profiler.py"
MAPPER_SCRIPT="01-Intelligent-Recon/automated_recon/attack_surface_mapper.py"
REPORT_DIR="01-Intelligent-Recon/reports"

# --- Functions ---
print_usage() {
    echo "Usage: $0 <target_domain>"
    echo "Example: $0 example.com"
}

# --- Main Script ---
# Check if a target domain is provided
if [ -z "$1" ]; then
    print_usage
    exit 1
fi

TARGET=$1
TIMESTAMP=$(date +%Y-%m-%d_%H%M%S)
REPORT_FILE="${REPORT_DIR}/recon_report_${TARGET}_${TIMESTAMP}.txt"

# Ensure the report directory exists
mkdir -p $REPORT_DIR

echo "Starting automated reconnaissance on: $TARGET"
echo "The report will be saved to: $REPORT_FILE"
echo "-------------------------------------------"

# Create and write the header to the report file
{
    echo "Automated Reconnaissance Report"
    echo "Target: $TARGET"
    echo "Date: $(date)"
    echo "==========================================="
    echo ""
} > "$REPORT_FILE"

# Run the Target Profiler
echo "[*] Running Target Profiler..."
{
    echo "### Target Profiler Results ###"
    echo ""
    python3 "$PROFILER_SCRIPT" "$TARGET"
    echo ""
    echo "==========================================="
    echo ""
} >> "$REPORT_FILE" 2>&1
echo "[+] Target Profiler finished."

# Run the Attack Surface Mapper
echo "[*] Running Attack Surface Mapper..."
{
    echo "### Attack Surface Mapper Results ###"
    echo ""
    python3 "$MAPPER_SCRIPT" "$TARGET"
    echo ""
} >> "$REPORT_FILE" 2>&1
echo "[+] Attack Surface Mapper finished."

echo "-------------------------------------------"
echo "Automated reconnaissance complete."
echo "Report available at: $REPORT_FILE"
