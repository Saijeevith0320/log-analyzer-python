#!/usr/bin/env python3
import re
import argparse
import pandas as pd

FAILED_LOGIN_PATTERN = r"Failed password for"
INVALID_USER_PATTERN = r"Invalid user"
ROOT_LOGIN_PATTERN = r"session opened for user root"
IP_PATTERN = r"(\d{1,3}\.){3}\d{1,3}"

def parse_logs(log_file):
    suspicious_events = []
    with open(log_file, "r", encoding="utf-8") as file:
        for line in file:
            match_ip = re.search(IP_PATTERN, line)
            ip_addr = match_ip.group() if match_ip else "N/A"
            if re.search(FAILED_LOGIN_PATTERN, line):
                suspicious_events.append(["Failed Login", line.strip(), ip_addr])
            elif re.search(INVALID_USER_PATTERN, line):
                suspicious_events.append(["Invalid User Attempt", line.strip(), ip_addr])
            elif re.search(ROOT_LOGIN_PATTERN, line):
                suspicious_events.append(["Root Login", line.strip(), ip_addr])
    return suspicious_events

def generate_report(events, output_file):
    df = pd.DataFrame(events, columns=["Event Type", "Log Entry", "IP Address"])
    df.to_csv(output_file, index=False)
    print(f"[+] Security report generated: {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automated Log Analyzer & Suspicious Activity Detector")
    parser.add_argument("--logfile", required=True, help="Path to log file to analyze")
    parser.add_argument("--output", default="security_report.csv", help="Output CSV file name")
    args = parser.parse_args()

    events = parse_logs(args.logfile)
    if events:
        print(f"[+] Detected {len(events)} suspicious events.")
        generate_report(events, args.output)
    else:
        print("[-] No suspicious events found. System looks clean!")
