"""
Risk Scoring & Policy Engine for AegisNIDS.
Upgrades binary 0.5 decision boundary to a realistic 3-tier risk-based policy:
  - LOW RISK (0 - 29): ALLOW -> Internal Subnet
  - MEDIUM RISK (30 - 69): MONITOR -> SOC Alert & Telemetry Watchlist
  - HIGH RISK (70 - 100): QUARANTINE -> Layer 2 Honeypot Sinkhole
Also provides attack category classification and MITRE ATT&CK mapping.
"""

def evaluate_policy(attack_probability, features=None, packets=None):
    """
    Evaluate policy based on calibrated risk score.
    
    Args:
        attack_probability: float between 0.0 and 1.0 from ML model
        features: dict of 12 extracted temporal features
        packets: list of packet dicts in the flow
        
    Returns:
        dict containing risk score, tier, policy, action, and MITRE mapping
    """
    risk_score = round(attack_probability * 100, 1)
    
    if risk_score < 30.0:
        risk_level = "LOW"
        policy = "ALLOW"
        policy_action = "FORWARD_TO_INTERNAL_NETWORK"
        status_color = "EMERALD"
        description = "Flow exhibits regular human/application timing characteristics. Approved for production egress."
    elif risk_score < 70.0:
        risk_level = "MEDIUM"
        policy = "MONITOR"
        policy_action = "FLAG_FOR_ANALYST_REVIEW"
        status_color = "AMBER"
        description = "Flow displays anomalous timing variance exceeding baseline tolerance. Placed on active watchlist."
    else:
        risk_level = "HIGH"
        policy = "QUARANTINE"
        policy_action = "REROUTE_TO_HONEYPOT_SINKHOLE"
        status_color = "ROSE"
        description = "High-confidence automated malicious signature detected. Diverted to Layer 2 Honeypot decoy."
        
    # Attack Category Classifier
    attack_category, mitre_ttp = classify_attack_category(risk_score, features, packets)
    
    return {
        'risk_score': risk_score,
        'risk_level': risk_level,
        'policy': policy,
        'policy_action': policy_action,
        'status_color': status_color,
        'description': description,
        'attack_category': attack_category,
        'mitre_ttp': mitre_ttp
    }

def classify_attack_category(risk_score, features=None, packets=None):
    """
    Classify flow into standard cybersecurity attack taxonomy.
    """
    if risk_score < 30.0:
        return "BENIGN", "N/A"
        
    target_port = 80
    if packets and len(packets) > 0:
        target_port = packets[0].get('dst_port', 80)
        
    features = features or {}
    idle_max = features.get('Idle Max', 0)
    flow_duration = features.get('Flow Duration', 0)
    flow_iat_mean = features.get('Flow IAT Mean', 0)
    
    # Slowloris: excessive idle gaps designed to tie up sockets
    if idle_max > 500000:
        return "DOS_SLOWLORIS", "T1499.003 - Endpoint Denial of Service: App Exhaustion"
        
    # Port scan: multiple target ports or uniform low packet bursts
    if packets and len(packets) > 1:
        ports = set(p.get('dst_port') for p in packets)
        if len(ports) > 2:
            return "RECON_PORT_SCAN", "T1046 - Network Service Scanning"
            
    # Brute force: SSH (22), FTP (21), RDP (3389)
    if target_port in [22, 21, 3389]:
        return "BRUTE_FORCE", "T1110 - Brute Force Authentication"
        
    # DDoS SYN Flood: high volume, sub-millisecond IAT
    if flow_iat_mean < 2000 and flow_duration < 50000:
        return "DDOS_SYN_FLOOD", "T1498.001 - Network Denial of Service: Direct Flood"
        
    # Generic DoS / Botnet
    if risk_score >= 85.0:
        return "DDOS_FLOOD", "T1498 - Network Denial of Service"
    else:
        return "ANOMALOUS_BURST", "T1071 - Application Layer Protocol"
