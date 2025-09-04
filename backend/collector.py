import re
import requests
import datetime

API_URL = "http://127.0.0.1:8000"
OSINT_FILE_PATH = "data/osint_feed.txt"

# Regex patterns for different IOC types
IOC_PATTERNS = {
    "ipv4": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    "domain": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
    "file_hash_sha256": r"\b[A-Fa-f0-9]{64}\b",
}

def find_iocs(text):
    """Finds all IOCs in a given text using regex patterns."""
    iocs = []
    for ioc_type, pattern in IOC_PATTERNS.items():
        matches = re.findall(pattern, text)
        for match in matches:
            # Basic filtering for private IPs, could be improved
            if ioc_type == "ipv4" and (match.startswith("192.168.") or match.startswith("10.")):
                continue
            iocs.append({"indicator_type": ioc_type, "value": match})
    return iocs

def create_or_get_threat(name, description):
    """Creates a new threat or gets it if it already exists."""
    try:
        # For this simple collector, we'll create a new threat every time
        # A more advanced collector would check if a similar threat exists
        payload = {"name": name, "description": description, "threat_class": "osint"}
        response = requests.post(f"{API_URL}/threats/", json=payload)
        response.raise_for_status()
        threat_data = response.json()
        print(f"Successfully created threat '{name}' with ID {threat_data['id']}")
        return threat_data
    except requests.exceptions.RequestException as e:
        print(f"Error creating threat: {e}")
        # If creation fails (e.g., name already exists), we could try to GET it
        # but for now, we'll exit.
        return None

def add_indicator_to_threat(threat_id, indicator):
    """Adds a single IOC to a given threat ID."""
    try:
        response = requests.post(f"{API_URL}/threats/{threat_id}/indicators/", json=indicator)
        response.raise_for_status()
        print(f"Successfully added indicator: {indicator['value']}")
    except requests.exceptions.RequestException as e:
        print(f"Error adding indicator {indicator['value']}: {e}")

def main():
    """Main function to run the collector."""
    print("Starting OSINT collector...")

    # 1. Read the OSINT data source
    try:
        with open(OSINT_FILE_PATH, "r") as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: OSINT data file not found at {OSINT_FILE_PATH}")
        return

    # 2. Find all potential IOCs in the text
    iocs = find_iocs(content)
    if not iocs:
        print("No new IOCs found.")
        return

    print(f"Found {len(iocs)} potential IOCs.")

    # 3. Create a threat to group these IOCs
    threat_name = f"OSINT Feed - {datetime.date.today()}"
    threat_description = "Automated threat report from OSINT text feed."
    threat = create_or_get_threat(threat_name, threat_description)

    if not threat:
        print("Could not create or retrieve a threat. Aborting.")
        return

    # 4. Add each IOC to the threat via the API
    threat_id = threat["id"]
    for ioc in iocs:
        add_indicator_to_threat(threat_id, ioc)

    print("OSINT collector finished.")

if __name__ == "__main__":
    # Note: The API server must be running for this script to work.
    main()
