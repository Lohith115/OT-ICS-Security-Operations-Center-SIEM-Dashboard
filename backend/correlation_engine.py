"""
correlation_engine.py
Analyzes parsed logs to detect security threats.
Implements rules for SSH Brute Force, Web Scanning, and Suspicious Access.
"""

from typing import Dict, Optional
from datetime import datetime
from database import db_manager
from mitre_attack_mapper import enrich_alert_with_mitre
import requests
from threat_intel import ThreatIntelligence
threat_intel = ThreatIntelligence()

_geoip_cache = {}

def get_geoip_data(ip: str):
    if ip in _geoip_cache:
        return _geoip_cache[ip]
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
        if response.get('status') == 'success':
            result = response.get('lat'), response.get('lon')
            _geoip_cache[ip] = result
            return result
    except:
        pass
    _geoip_cache[ip] = (None, None)
    return None, None


class CorrelationEngine:
    """
    Detects security incidents based on log patterns.
    """

    # --- Configuration Constants ---
    # SSH Brute Force: 5+ failures in 5 minutes
    SSH_FAILURE_THRESHOLD = 5
    SSH_TIME_WINDOW_MINUTES = 5

    # Web Scanning: 10+ 404 errors in 5 minutes
    WEB_404_THRESHOLD = 10
    WEB_TIME_WINDOW_MINUTES = 5

    def __init__(self):
        self.db = db_manager

    def analyze_log(self, log_data: Dict) -> Optional[Dict]:
        """
        Main entry point. Analyzes a single parsed log entry.
        Returns an alert dictionary if a rule is triggered, otherwise None.
        """
        log_type = log_data.get('log_type')
        print(f"DEBUG: Analyzing {log_type} log from {log_data.get('source_ip')}")
        
        alert = None

        if log_type == 'SSH':
            alert = self._check_ssh_brute_force(log_data)
        
        elif log_type == 'HTTP':
            # Check for web scanning (404s)
            alert = alert or self._check_web_scanning(log_data)
            # Check for admin panel probing
            alert = alert or self._check_admin_probing(log_data)

        return alert
   
    def _check_ssh_brute_force(self, log_data: Dict) -> Optional[Dict]:
        """
        Rule: 5 or more failed SSH attempts from same IP in 5 minutes.
        """
        if log_data.get('severity') != 'Failed':
            return None

        ip = log_data['source_ip']
        current_count = self.db.count_failed_attempts(ip, self.SSH_TIME_WINDOW_MINUTES)
        total_attempts = current_count + 1

        if total_attempts >= self.SSH_FAILURE_THRESHOLD:
            description = f"SSH Brute Force detected: {total_attempts} failed attempts from {ip}"
            intel_summary = threat_intel.get_threat_summary(ip)
            description = f"{description} | TI: {intel_summary}"
            
            # Get Location
            lat, lon = get_geoip_data(ip)
            
            # Create base alert
            alert_data = {
                "type": "SSH_BRUTE_FORCE",
                "ip": ip,
                "description": description
            }
            
            # Enrich with MITRE context
            alert_data = enrich_alert_with_mitre(alert_data)
            
            alert_id = self.db.insert_alert(
                timestamp=datetime.now().isoformat(),
                alert_type=alert_data["type"],
                severity="Critical",
                source_ip=ip,
                description=description,
                related_log_ids=[],
                latitude=lat,
                longitude=lon,
                mitre_tactic=alert_data.get('mitre_tactic'),
                mitre_technique=alert_data.get('mitre_technique'),
                risk_score=alert_data.get('risk_score')
            )
            
            print(f"DEBUG: ALERT GENERATED: {alert_data['type']} (ID: {alert_id})")
            alert_data["alert_id"] = alert_id
            return alert_data

        return None


    

    def _check_web_scanning(self, log_data: Dict) -> Optional[Dict]:
        """
        Rule: 10 or more 404 errors from same IP in 5 minutes.
        """
        if '404' not in log_data.get('message', ''):
            return None

        ip = log_data['source_ip']
        current_count = self.db.count_404_errors(ip, self.WEB_TIME_WINDOW_MINUTES)
        total_attempts = current_count + 1

        if total_attempts >= self.WEB_404_THRESHOLD:
            description = f"Web Scanning detected: {total_attempts} 404 errors from {ip}"
            
            # Get Location
            lat, lon = get_geoip_data(ip)
            
            # Create base alert
            alert_data = {
                "type": "WEB_SCANNING",
                "ip": ip,
                "description": description
            }
            
            # Enrich with MITRE context
            alert_data = enrich_alert_with_mitre(alert_data)
            
            alert_id = self.db.insert_alert(
                timestamp=datetime.now().isoformat(),
                alert_type=alert_data["type"],
                severity="High",
                source_ip=ip,
                description=description,
                related_log_ids=[],
                latitude=lat,
                longitude=lon,
                mitre_tactic=alert_data.get('mitre_tactic'),
                mitre_technique=alert_data.get('mitre_technique'),
                risk_score=alert_data.get('risk_score')
            )
            
            alert_data["alert_id"] = alert_id
            return alert_data

        return None

    def _check_admin_probing(self, log_data: Dict) -> Optional[Dict]:
        """
        Rule: Attempts to access sensitive paths like /admin, /wp-login.php
        """
        message = log_data.get('message', '')
        sensitive_paths = ['/admin', '/wp-login', '/phpmyadmin', '/.env']
        
        if any(path in message for path in sensitive_paths):
            ip = log_data['source_ip']
            description = f"Suspicious Admin Access attempt from {ip} - Path: {message}"
            
            # Get Location
            lat, lon = get_geoip_data(ip)
            
            # Create base alert
            alert_data = {
                "type": "ADMIN_PROBE",
                "ip": ip,
                "description": description
            }
            
            # Enrich with MITRE context
            alert_data = enrich_alert_with_mitre(alert_data)
            
            alert_id = self.db.insert_alert(
                timestamp=datetime.now().isoformat(),
                alert_type=alert_data["type"],
                severity="Medium",
                source_ip=ip,
                description=description,
                related_log_ids=[],
                latitude=lat,
                longitude=lon,
                mitre_tactic=alert_data.get('mitre_tactic'),
                mitre_technique=alert_data.get('mitre_technique'),
                risk_score=alert_data.get('risk_score')
            )
            
            alert_data["alert_id"] = alert_id
            return alert_data

        return None


# Singleton instance
correlation_engine = CorrelationEngine()
