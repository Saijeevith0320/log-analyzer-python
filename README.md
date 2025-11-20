# Automated Log Analyzer & Suspicious Activity Detector (Python SOC Tool)

A Python-based security automation tool that scans Linux system logs to detect suspicious activity.

## Features
- Detects failed SSH login attempts
- Flags invalid user access attempts
- Detects root logins
- Extracts suspicious IPs
- Generates CSV security report

## Installation
```
pip install -r requirements.txt
```

## Usage
```
python log_analyzer.py --logfile sample_logs.txt --output security_report.csv
```

## Author
Sai Jeevith  
GitHub: https://github.com/Saijeevith0320
