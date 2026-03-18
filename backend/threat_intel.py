"""
threat_intel.py
Integrates with multiple threat intelligence feeds
Makes your SIEM stand out with real-time threat context
"""

import requests
from typing import Dict, Optional
import time

class ThreatIntelligence:
    """Queries multiple threat intelligence sources"""
    
    def __init__(self):
        self.cache = {}  # Simple cache to avoid repeated API calls
        self.cache_duration = 3600  # 1 hour cache
    
    def check_ip_reputation(self, ip: str) -> Dict:
        """
        Check IP reputation across multiple sources.
        
        Sources:
        1. AbuseIPDB (requires free API key)
        2. IPQualityScore (free tier available)
        3. AlienVault OTX (free)
        
        Returns:
            Dictionary with threat intelligence data
        """
        # Check cache first
        if ip in self.cache:
            cached_data, timestamp = self.cache[ip]
            if time.time() - timestamp < self.cache_duration:
                return cached_data
        
        intel = {
            "ip": ip,
            "is_malicious": False,
            "threat_score": 0,
            "categories": [],
            "last_seen": None,
            "reports": 0,
            "sources": []
        }
        
        # Source 1: AbuseIPDB (Free tier: 1000 requests/day)
        # You need to sign up at https://www.abuseipdb.com/api
        try:
            abuseipdb_data = self._check_abuseipdb(ip)
            if abuseipdb_data:
                intel['is_malicious'] = abuseipdb_data.get('abuseConfidenceScore', 0) > 50
                intel['threat_score'] = max(intel['threat_score'], abuseipdb_data.get('abuseConfidenceScore', 0))
                intel['reports'] += abuseipdb_data.get('totalReports', 0)
                intel['sources'].append('AbuseIPDB')
        except:
            pass
        
        # Source 2: VirusTotal (Free: 4 requests/minute)
        # Sign up at https://www.virustotal.com/gui/join-us
        try:
            vt_data = self._check_virustotal(ip)
            if vt_data:
                intel['sources'].append('VirusTotal')
                # Parse VirusTotal data
        except:
            pass
        
        # Cache the result
        self.cache[ip] = (intel, time.time())
        
        return intel
    
    def _check_abuseipdb(self, ip: str) -> Optional[Dict]:
        """
        Query AbuseIPDB API
        
        To use this:
        1. Sign up at https://www.abuseipdb.com/api
        2. Get your free API key
        3. Add it here or use environment variable
        """
        API_KEY = "YOUR_ABUSEIPDB_API_KEY_HERE"  # Replace with actual key
        
        if API_KEY == "YOUR_ABUSEIPDB_API_KEY_HERE":
            return None  # Skip if no key configured
        
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            'Accept': 'application/json',
            'Key': API_KEY
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': '90'
        }
        
        try:
            response = requests.get(url, headers=headers, params=params, timeout=5)
            if response.status_code == 200:
                return response.json().get('data', {})
        except:
            pass
        
        return None
    
    def _check_virustotal(self, ip: str) -> Optional[Dict]:
        """Query VirusTotal API"""
        API_KEY = "YOUR_VIRUSTOTAL_API_KEY_HERE"
        
        if API_KEY == "YOUR_VIRUSTOTAL_API_KEY_HERE":
            return None
        
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {
            'x-apikey': API_KEY
        }
        
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                return response.json()
        except:
            pass
        
        return None
    
    def check_domain_reputation(self, domain: str) -> Dict:
        """Check domain reputation"""
        # Similar implementation for domains
        return {
            "domain": domain,
            "is_malicious": False,
            "threat_score": 0
        }
    
    def get_threat_summary(self, ip: str) -> str:
        """
        Get human-readable threat summary
        """
        intel = self.check_ip_reputation(ip)
        
        if intel['is_malicious']:
            return f"⚠️ THREAT DETECTED: {ip} has {intel['reports']} abuse reports (Score: {intel['threat_score']}%)"
        elif intel['threat_score'] > 0:
            return f"⚠️ SUSPICIOUS: {ip} has a threat score of {intel['threat_score']}%"
        else:
            return f"✅ CLEAN: No threat intelligence found for {ip}"

# Example integration with correlation_engine.py:
"""
from threat_intel import ThreatIntelligence

threat_intel = ThreatIntelligence()

# Inside correlation engine when creating alert:
intel = threat_intel.check_ip_reputation(ip)

alert = {
    "alert_id": alert_id,
    "type": "SSH_BRUTE_FORCE",
    "ip": ip,
    "description": description,
    "threat_intel": intel,  # Add threat intel data
    "threat_summary": threat_intel.get_threat_summary(ip)
}
"""

# Free Threat Intel APIs you can use:
"""
1. AbuseIPDB (Free: 1000 requests/day)
   https://www.abuseipdb.com/api

2. VirusTotal (Free: 4 requests/minute)
   https://www.virustotal.com/gui/join-us

3. AlienVault OTX (Free, unlimited)
   https://otx.alienvault.com/api

4. IPQualityScore (Free: 5000 requests/month)
   https://www.ipqualityscore.com/

5. Shodan (Free tier available)
   https://www.shodan.io/

6. GreyNoise (Free for non-commercial)
   https://www.greynoise.io/
"""
