"""
log_parser.py
Parses raw log lines into structured dictionaries.
Supports SSH Auth logs and Apache/Nginx Access logs.
"""

import re
import datetime
from typing import Dict, Optional, List


def parse_ssh_timestamp(time_str: str) -> str:
    """
    Converts SSH log timestamp (e.g., 'Jan 15 10:30:45') to ISO format.
    Assumes the current year since SSH logs typically omit the year.
    """
    try:
        current_year = datetime.datetime.now().year
        # Format: "Jan 15 10:30:45"
        dt = datetime.datetime.strptime(f"{current_year} {time_str}", "%Y %b %d %H:%M:%S")
        return dt.isoformat()
    except ValueError:
        return datetime.datetime.now().isoformat()


def parse_apache_timestamp(time_str: str) -> str:
    """
    Converts Apache log timestamp (e.g., '15/Jan/2024:10:30:45 +0000') to ISO format.
    """
    try:
        # Format: "15/Jan/2024:10:30:45 +0000"
        dt = datetime.datetime.strptime(time_str.split()[0], "%d/%b/%Y:%H:%M:%S")
        return dt.isoformat()
    except ValueError:
        return datetime.datetime.now().isoformat()


def parse_ssh_log(line: str) -> Optional[Dict[str, str]]:
    """
    Parses SSH auth logs.
    """
    # Example: Jan 15 10:30:45 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2
    ssh_pattern = re.compile(
        r'^(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+'
        r'(?P<host>\S+)\s+'
        r'sshd\[\d+\]:\s+'
        r'(?P<event>Failed password|Accepted password)\s+'
        r'for\s+(?P<user>\S+)\s+'
        r'from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)'
    )

    match = ssh_pattern.match(line)
    if match:
        data = match.groupdict()
        
        if "Failed" in data['event']:
            severity = "Failed"
        else:
            severity = "Success"
            
        return {
            "timestamp": parse_ssh_timestamp(data['timestamp']),
            "source_ip": data['ip'],
            "log_type": "SSH",
            "severity": severity,
            "message": f"{data['event']} for user {data['user']}",
            "raw_log": line
        }
    
    return None


def parse_apache_log(line: str) -> Optional[Dict[str, str]]:
    """
    Parses Apache/Nginx access logs.
    """
    # Example: 192.168.1.100 - - [15/Jan/2024:10:30:45 +0000] "GET /admin/login HTTP/1.1" 404 512
    apache_pattern = re.compile(
        r'^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+'
        r'-\s+-\s+\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\w+)\s+'
        r'(?P<path>[^\s]+)\s+HTTP/\d\.\d"\s+'
        r'(?P<status>\d+)'
    )

    match = apache_pattern.match(line)
    if match:
        data = match.groupdict()
        
        status_code = int(data['status'])
        if status_code >= 500:
            severity = "Critical"
        elif status_code >= 400:
            severity = "Error"
        elif status_code >= 300:
            severity = "Warning"
        else:
            severity = "Info"

        return {
            "timestamp": parse_apache_timestamp(data['timestamp']),
            "source_ip": data['ip'],
            "log_type": "HTTP",
            "severity": severity,
            "message": f"{data['method']} {data['path']} {data['status']}",
            "raw_log": line
        }

    return None


# ---------------------------------------------------------
# IMPORTANT: This function must be UNINDENTED (start of line)
# ---------------------------------------------------------
def parse_log_line(line: str) -> Optional[Dict[str, str]]:
    """
    Main entry point for parsing.
    Detects log type and routes to the appropriate parser.
    """
    if not line or not line.strip():
        return None

    # Try parsing as SSH first
    parsed = parse_ssh_log(line)
    if parsed:
        return parsed

    # Try parsing as Apache/Nginx
    parsed = parse_apache_log(line)
    if parsed:
        return parsed

    # If no match, return None (Unknown format)
    return None


# --- Testing block ---
if __name__ == "__main__":
    ssh_sample = "Jan 15 10:30:45 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2"
    apache_sample = '192.168.1.100 - - [15/Jan/2024:10:30:45 +0000] "GET /admin/login HTTP/1.1" 404 512'

    print("Testing SSH Parser:")
    print(parse_log_line(ssh_sample))

    print("\nTesting Apache Parser:")
    print(parse_log_line(apache_sample))
