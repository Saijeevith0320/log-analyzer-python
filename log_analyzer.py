import re
from datetime import datetime
import pandas as pd

FAILED_LOGIN_PATTERN = r"Failed password for"
INVALID_USER_PATTERN = r"Invalid user"
ROOT_LOGIN_PATTERN = r"session opened for user root"
IP_PATTERN = r"(\d{1,3}\.){3}\d{1,3}"

def parse_logs(log_file):
    suspicious_events = []

    with open(log_file, "r", encoding="utf-8") as file:
        for line in file:
            timestamp = "Unknown"
            match_ip = re.search(IP_PATTERN, line)
            ip_addr = match_ip.group() if match_ip else "N/A"

            if re.search(FAILED_LOGIN_PATTERN, line):
                suspicious_events.append(["Failed Login", line.strip(), ip_addr, timestamp])
            elif re.search(INVALID_USER_PATTERN, line):
                suspicious_events.append(["Invalid User Attempt", line.strip(), ip_addr, timestamp])
            elif re.search(ROOT_LOGIN_PATTERN, line):
                suspicious_events.append(["Root Login", line.strip(), ip_addr, timestamp])

    return suspicious_events

def generate_report(events, output_file="security_report.csv"):
    df = pd.DataFrame(events, columns=["Event Type", "Log Entry", "IP Address", "Timestamp"])
    df.to_csv(output_file, index=False)
    print(f"Security report generated: {output_file}")

if __name__ == "__main__":
    print("=== Automated Log Analyzer & Suspicious Activity Detector ===")
    log_file = input("Enter path to your log file: ")

    events = parse_logs(log_file)

    if events:
        print(f"[+] Detected {len(events)} suspicious events.")
        generate_report(events)
    else:
        print("[-] No suspicious events found. System looks clean!")
