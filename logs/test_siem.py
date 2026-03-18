#!/usr/bin/env python3
"""
test_siem.py
Comprehensive test script for SIEM Dashboard
Generates various attack scenarios to trigger all correlation rules
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
        else:
            print(f"❌ Error: {response.status_code}")
    except Exception as e:
        print(f"❌ Connection Error: {e}")
    time.sleep(1)

def test_ssh_brute_force():
    """Test SSH Brute Force Detection (5+ failed attempts)"""
    print_header("TEST 1: SSH Brute Force Attack")
    
    logs = [
        "Jan 15 10:30:45 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Jan 15 10:30:46 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Jan 15 10:30:47 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Jan 15 10:30:48 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Jan 15 10:30:49 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Jan 15 10:30:50 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2",
    ]
    
    send_logs(logs, "6 failed SSH attempts from 192.168.1.100 (should trigger alert)")

def test_web_scanning():
    """Test Web Scanning Detection (10+ 404 errors)"""
    print_header("TEST 2: Web Directory Scanning")
    
    logs = [
        '192.168.1.200 - - [15/Jan/2024:10:30:45 +0000] "GET /admin HTTP/1.1" 404 512',
        '192.168.1.200 - - [15/Jan/2024:10:30:46 +0000] "GET /backup HTTP/1.1" 404 512',
        '192.168.1.200 - - [15/Jan/2024:10:30:47 +0000] "GET /old HTTP/1.1" 404 512',
        '192.168.1.200 - - [15/Jan/2024:10:30:48 +0000] "GET /test HTTP/1.1" 404 512',
        '192.168.1.200 - - [15/Jan/2024:10:30:49 +0000] "GET /dev HTTP/1.1" 404 512',
        '192.168.1.200 - - [15/Jan/2024:10:30:50 +0000] "GET /config HTTP/1.1" 404 512',
        '192.168.1.200 - - [15/Jan/2024:10:30:51 +0000] "GET /uploads HTTP/1.1" 404 512',
        '192.168.1.200 - - [15/Jan/2024:10:30:52 +0000] "GET /files HTTP/1.1" 404 512',
        '192.168.1.200 - - [15/Jan/2024:10:30:53 +0000] "GET /data HTTP/1.1" 404 512',
        '192.168.1.200 - - [15/Jan/2024:10:30:54 +0000] "GET /secret HTTP/1.1" 404 512',
        '192.168.1.200 - - [15/Jan/2024:10:30:55 +0000] "GET /private HTTP/1.1" 404 512',
    ]
    
    send_logs(logs, "11 × 404 errors from 192.168.1.200 (should trigger alert)")

def test_admin_probing():
    """Test Admin Panel Probing Detection"""
    print_header("TEST 3: Admin Panel Reconnaissance")
    
    logs = [
        '45.142.120.10 - - [15/Jan/2024:10:30:45 +0000] "GET /admin/login HTTP/1.1" 403 256',
        '45.142.120.10 - - [15/Jan/2024:10:30:46 +0000] "GET /wp-login.php HTTP/1.1" 404 128',
        '45.142.120.10 - - [15/Jan/2024:10:30:47 +0000] "GET /phpmyadmin HTTP/1.1" 404 128',
        '45.142.120.10 - - [15/Jan/2024:10:30:48 +0000] "GET /.env HTTP/1.1" 404 128',
    ]
    
    send_logs(logs, "Admin panel probing from 45.142.120.10 (should trigger 4 alerts)")

def test_normal_traffic():
    """Test Normal Traffic (Should NOT trigger alerts)"""
    print_header("TEST 4: Normal Traffic (No Alerts Expected)")
    
    logs = [
        "Jan 15 10:31:00 server sshd[12345]: Accepted password for admin from 10.0.0.50 port 22 ssh2",
        '10.0.0.50 - - [15/Jan/2024:10:31:15 +0000] "GET /index.html HTTP/1.1" 200 1024',
        '10.0.0.50 - - [15/Jan/2024:10:31:16 +0000] "POST /api/users HTTP/1.1" 200 512',
        '10.0.0.50 - - [15/Jan/2024:10:31:17 +0000] "GET /dashboard HTTP/1.1" 200 2048',
    ]
    
    send_logs(logs, "Legitimate traffic (no alerts expected)")

def test_mixed_scenario():
    """Test Real-World Mixed Scenario"""
    print_header("TEST 5: Real-World Mixed Attack Scenario")
    
    logs = [
        # Normal user activity
        "Jan 15 10:40:00 server sshd[10001]: Accepted password for user1 from 10.0.0.100 port 22 ssh2",
        '10.0.0.100 - - [15/Jan/2024:10:40:05 +0000] "GET /dashboard HTTP/1.1" 200 2048',
        
        # Attacker #1: SSH Brute Force
        "Jan 15 10:40:10 server sshd[10002]: Failed password for root from 203.0.113.50 port 22 ssh2",
        "Jan 15 10:40:11 server sshd[10002]: Failed password for admin from 203.0.113.50 port 22 ssh2",
        "Jan 15 10:40:12 server sshd[10002]: Failed password for user from 203.0.113.50 port 22 ssh2",
        "Jan 15 10:40:13 server sshd[10002]: Failed password for test from 203.0.113.50 port 22 ssh2",
        "Jan 15 10:40:14 server sshd[10002]: Failed password for guest from 203.0.113.50 port 22 ssh2",
        
        # Attacker #2: Web Scanning
        '198.51.100.42 - - [15/Jan/2024:10:40:20 +0000] "GET /admin HTTP/1.1" 404 128',
        '198.51.100.42 - - [15/Jan/2024:10:40:21 +0000] "GET /wp-admin HTTP/1.1" 404 128',
        
        # More normal traffic
        '10.0.0.100 - - [15/Jan/2024:10:40:25 +0000] "POST /api/data HTTP/1.1" 200 512',
    ]
    
    send_logs(logs, "Mixed scenario: 1 SSH brute force + web probing + normal traffic")

def check_dashboard_stats():
    """Check current dashboard statistics"""
    print_header("DASHBOARD STATISTICS")
    
    try:
        response = requests.get(f"{API_URL}/stats")
        if response.status_code == 200:
            stats = response.json()
            print(f"📊 Total Logs: {stats.get('total_logs', 0)}")
            print(f"🚨 Total Alerts: {stats.get('total_alerts', 0)}")
            
            if stats.get('top_attackers'):
                print(f"\n🎯 Top Attacking IPs:")
                for attacker in stats['top_attackers'][:5]:
                    print(f"   • {attacker['ip']}: {attacker['count']} alerts")
        else:
            print(f"❌ Error fetching stats: {response.status_code}")
    except Exception as e:
        print(f"❌ Connection Error: {e}")

def main():
    print("\n")
    print("╔═══════════════════════════════════════════════════════════╗")
    print("║         SIEM Dashboard - Comprehensive Test Suite        ║")
    print("╚═══════════════════════════════════════════════════════════╝")
    print(f"\n⏰ Test Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Run all tests
    test_ssh_brute_force()
    test_web_scanning()
    test_admin_probing()
    test_normal_traffic()
    test_mixed_scenario()
    
    # Wait for processing
    print("\n⏳ Waiting 3 seconds for processing...")
    time.sleep(3)
    
    # Check final stats
    check_dashboard_stats()
    
    print("\n")
    print("╔═══════════════════════════════════════════════════════════╗")
    print("║                    Test Suite Complete!                   ║")
    print("║                                                            ║")
    print("║  📊 Open http://localhost:5000 to view the dashboard      ║")
    print("║  🗺️  Check the global map for attack origins               ║")
    print("║  🚨 Review the alerts panel for triggered rules           ║")
    print("╚═══════════════════════════════════════════════════════════╝")
    print("\n")

if __name__ == "__main__":
    main()
