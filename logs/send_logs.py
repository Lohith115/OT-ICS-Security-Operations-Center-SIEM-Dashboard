import requests
import json

# The API endpoint
url = "http://localhost:5000/api/ingest"

# Sample logs to simulate an attack
payload = {
    "logs": [
        # 5 Failed SSH attempts (Should trigger SSH Brute Force Alert)
        "Jan 15 10:30:45 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Jan 15 10:30:46 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Jan 15 10:30:47 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Jan 15 10:30:48 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Jan 15 10:30:49 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2",
        
        # A successful login (just for variety)
        "Jan 15 10:31:00 server sshd[12345]: Accepted password for admin from 10.0.0.50 port 22 ssh2",
        
        # Web logs with 404s (Should trigger Admin Probing Alert)
        '192.168.1.100 - - [15/Jan/2024:10:30:45 +0000] "GET /admin/login HTTP/1.1" 404 512',
        '192.168.1.100 - - [15/Jan/2024:10:30:46 +0000] "GET /wp-admin HTTP/1.1" 404 128',
        
        # Normal web traffic
        '10.0.0.50 - - [15/Jan/2024:10:31:15 +0000] "POST /api/users HTTP/1.1" 200 1024'
    ]
}

try:
    response = requests.post(url, json=payload)
    print(f"Status Code: {response.status_code}")
    print("Response:", response.json())
except Exception as e:
    print(f"Error connecting to server: {e}")
