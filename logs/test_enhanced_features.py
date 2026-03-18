#!/usr/bin/env python3
"""
test_enhanced_features.py
Tests new SIEM features: MITRE ATT&CK Mapping and AI Anomaly Detection.
Includes SSH, Web Scanning, and Admin Probing.
"""

import requests
import time
import json
from datetime import datetime

API_URL = "http://localhost:5000/api"

def print_header(text):
    print(f"\n{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}\n")

def send_logs(logs, description):
    """Send logs to the SIEM API"""
    print(f"🔄 Sending: {description}")
    try:
        response = requests.post(f"{API_URL}/ingest", json={"logs": logs})
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Success: {data['processed']} logs processed, {data['alerts_triggered']} alerts triggered")
            return True
        else:
            print(f"❌ Error: {response.status_code}")
    except Exception as e:
        print(f"❌ Connection Error: {e}")
    return False

def verify_mitre_mapping():
    """Verify that alerts are enriched with MITRE context"""
    print_header("TEST: MITRE ATT&CK Enrichment Verification")
    
    # Use current time for logs
    now = datetime.now()
    timestamp = now.strftime("%b %d %H:%M:%S")
    timestamp_web = now.strftime("%d/%b/%Y:%H:%M:%S")

    # 1. Trigger SSH Brute Force
    ssh_logs = [
        f"{timestamp} server sshd[12345]: Failed password for root from 1.1.1.1 port 22 ssh2"
        for _ in range(6)
    ]
    send_logs(ssh_logs, "SSH Brute Force (Tactic: Initial Access)")

    # 2. Trigger Web Scanning
    web_logs = [
        f'2.2.2.2 - - [{timestamp_web} +0000] "GET /path{i} HTTP/1.1" 404 512'
        for i in range(12)
    ]
    send_logs(web_logs, "Web Scanning (Tactic: Reconnaissance)")

    # 3. Trigger Admin Probe
    admin_logs = [
        f'3.3.3.3 - - [{timestamp_web} +0000] "GET /wp-login.php HTTP/1.1" 404 128',
        f'3.3.3.3 - - [{timestamp_web} +0000] "GET /admin HTTP/1.1" 403 128',
        f'3.3.3.3 - - [{timestamp_web} +0000] "GET /.env HTTP/1.1" 404 128'
    ]
    send_logs(admin_logs, "Admin Probing (Tactic: Discovery)")
    
    time.sleep(2) 
    
    # Check API data
    try:
        response = requests.get(f"{API_URL}/alerts?limit=5")
        if response.status_code == 200:
            alerts = response.json()
            print("\n🔍 RECENT ALERTS VERIFICATION:")
            for alert in alerts:
                print(f"• {alert['alert_type']}: MITRE Tactic = {alert.get('mitre_tactic', 'N/A')}")
        else:
            print(f"❌ Error fetching alerts: {response.status_code}")
    except Exception as e:
        print(f"❌ Verification Error: {e}")

def trigger_ml_anomaly():
    """Trigger the AI Anomaly Detector"""
    print_header("TEST: AI Anomaly Detection (ML)")
    now = datetime.now()
    timestamp = now.strftime("%b %d %H:%M")
    
    logs = []
    for i in range(30):
        ip = f"10.99.0.{i}"
        logs.append(f"{timestamp}:{i:02d} server sshd[999]: Failed password for admin from {ip} port 22 ssh2")
    
    send_logs(logs, "Sending anomalous log pattern (Multi-IP burst failures)")
    
    time.sleep(2)

def main():
    print_header("SIEM ENHANCED FEATURES TEST")
    verify_mitre_mapping()
    trigger_ml_anomaly()
    
    print("\n🚀 Tests Finished. Please check your Dashboard UI.")

if __name__ == "__main__":
    main()
