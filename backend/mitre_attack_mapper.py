"""
mitre_attack_mapper.py
Maps security alerts to MITRE ATT&CK Framework techniques
This adds professional threat intelligence context to your SIEM
"""

# MITRE ATT&CK Mapping Database
ATTACK_MAPPING = {
    "SSH_BRUTE_FORCE": {
        "tactic": "TA0001 - Initial Access",
        "technique": "T1110.001 - Password Guessing",
        "description": "Adversary attempting to gain access through brute force password attacks",
        "mitigation": "Implement account lockout policies, multi-factor authentication",
        "severity_score": 8.5
    },
    "WEB_SCANNING": {
        "tactic": "TA0043 - Reconnaissance",
        "technique": "T1595.002 - Active Scanning: Vulnerability Scanning",
        "description": "Adversary probing web application for vulnerabilities",
        "mitigation": "Deploy WAF, implement rate limiting, use honeypots",
        "severity_score": 6.0
    },
    "ADMIN_PROBE": {
        "tactic": "TA0007 - Discovery",
        "technique": "T1083 - File and Directory Discovery",
        "description": "Adversary searching for admin interfaces and sensitive files",
        "mitigation": "Remove default admin paths, implement path obfuscation",
        "severity_score": 7.0
    },
    "SCADA_UNAUTHORIZED_ACCESS": {
        "tactic": "TA0108 - Initial Access (ICS)",
        "technique": "T0817 - Drive-by Compromise",
        "description": "Unauthorized access attempt to industrial control system",
        "mitigation": "Network segmentation, ICS-specific firewall rules",
        "severity_score": 9.5
    }
}

def get_mitre_context(alert_type: str) -> dict:
    """
    Returns MITRE ATT&CK context for a given alert type.
    
    Args:
        alert_type: Type of security alert (e.g., "SSH_BRUTE_FORCE")
    
    Returns:
        Dictionary with MITRE ATT&CK details
    """
    return ATTACK_MAPPING.get(alert_type, {
        "tactic": "TA0000 - Unknown",
        "technique": "T0000 - Unknown Technique",
        "description": "Alert type not yet mapped to MITRE framework",
        "mitigation": "Investigate and classify threat",
        "severity_score": 5.0
    })

def enrich_alert_with_mitre(alert: dict) -> dict:
    """
    Enriches an alert with MITRE ATT&CK context.
    
    Args:
        alert: Alert dictionary from correlation engine
    
    Returns:
        Enhanced alert with MITRE context
    """
    mitre_context = get_mitre_context(alert.get('type', 'UNKNOWN'))
    
    alert['mitre_tactic'] = mitre_context['tactic']
    alert['mitre_technique'] = mitre_context['technique']
    alert['mitre_description'] = mitre_context['description']
    alert['recommended_mitigation'] = mitre_context['mitigation']
    alert['risk_score'] = mitre_context['severity_score']
    
    return alert

def generate_attack_chain_report(alerts: list) -> dict:
    """
    Analyzes multiple alerts to detect potential attack chains.
    
    Args:
        alerts: List of alerts
    
    Returns:
        Attack chain analysis
    """
    tactics_seen = set()
    techniques_seen = []
    total_risk = 0
    
    for alert in alerts:
        mitre_context = get_mitre_context(alert.get('type'))
        tactics_seen.add(mitre_context['tactic'].split(' - ')[0])
        techniques_seen.append(mitre_context['technique'])
        total_risk += mitre_context['severity_score']
    
    return {
        "total_alerts": len(alerts),
        "unique_tactics": len(tactics_seen),
        "tactics": list(tactics_seen),
        "techniques": techniques_seen,
        "combined_risk_score": round(total_risk / len(alerts) if alerts else 0, 2),
        "attack_progression": len(tactics_seen) >= 3  # Multi-stage attack indicator
    }

# Example usage in correlation_engine.py:
"""
from mitre_attack_mapper import enrich_alert_with_mitre

# Inside correlation_engine.py, after creating alert:
alert = {
    "alert_id": alert_id,
    "type": "SSH_BRUTE_FORCE",
    "ip": ip,
    "description": description
}

# Enrich with MITRE context
alert = enrich_alert_with_mitre(alert)

return alert
"""
