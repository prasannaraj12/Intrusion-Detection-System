#!/usr/bin/env python3
"""
AegisNIDS Honeypot Session Telemetry & STIX 2.1 Threat Intel Exporter.
Exports active quarantine session telemetry and extracted Indicators of Compromise (IOCs)
to industry-standard JSON and STIX 2.1 bundle formats for SIEM / MISP ingestion.
"""
import os
import json
import uuid
import urllib.request
from datetime import datetime

API_BASE = "http://127.0.0.1:5000"
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app", "data")
os.makedirs(DATA_DIR, exist_ok=True)

def export_all():
    print("[*] Contacting AegisNIDS Layer 2 Honeypot API...")
    
    # 1. Fetch live telemetry from API endpoints
    try:
        req_sess = urllib.request.urlopen(f"{API_BASE}/api/honeypot/sessions", timeout=5)
        sessions_data = json.loads(req_sess.read().decode('utf-8'))
        
        req_iocs = urllib.request.urlopen(f"{API_BASE}/api/iocs", timeout=5)
        iocs_data = json.loads(req_iocs.read().decode('utf-8'))
    except Exception as e:
        print(f"[-] API connection failed ({e}). Loading from local storage...")
        from app.utils.honeypot_ioc import get_all_sessions, get_all_iocs
        sessions_data = {'sessions': get_all_sessions(), 'sessions_count': len(get_all_sessions())}
        iocs_data = {'iocs': get_all_iocs(), 'iocs_count': len(get_all_iocs())}

    sessions = sessions_data.get('sessions', [])
    iocs = iocs_data.get('iocs', [])

    # 2. Build Comprehensive Telemetry Report
    full_report = {
        "metadata": {
            "export_timestamp": datetime.utcnow().isoformat() + "Z",
            "generator": "AegisNIDS Layer 2 Autonomous Forensic Engine",
            "threat_defense_posture": "ELEVATED (DEFCON 2)",
            "quarantine_tier": "HIGH_RISK (Risk Score >= 70)",
            "honeypot_sandbox_status": "ONLINE",
            "sessions_count": len(sessions),
            "iocs_count": len(iocs)
        },
        "quarantined_sessions": sessions,
        "indicators_of_compromise": iocs
    }
    
    json_export_path = os.path.join(DATA_DIR, "honeypot_telemetry_export.json")
    with open(json_export_path, "w") as f:
        json.dump(full_report, f, indent=2)
    print(f"[+] Full Forensic Telemetry saved to: {json_export_path}")

    # 3. Build STIX 2.1 Threat Intel Bundle
    stix_objects = []
    sensor_id = f"identity--{uuid.uuid4()}"
    stix_objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": sensor_id,
        "created": datetime.utcnow().isoformat() + "Z",
        "modified": datetime.utcnow().isoformat() + "Z",
        "name": "AegisNIDS Autonomous Defense Sensor",
        "description": "Zero-DPI Temporal Intrusion Detection & Decoy Quarantine Platform",
        "identity_class": "system"
    })

    for item in iocs:
        ind_id = f"indicator--{uuid.uuid4()}"
        ioc_type = item.get("type", "IPv4")
        indicator_val = item.get("indicator", "")
        
        if ioc_type == "IPv4":
            pattern = f"[ipv4-addr:value = '{indicator_val}']"
        elif ioc_type == "SHA-256":
            pattern = f"[file:hashes.'SHA-256' = '{indicator_val}']"
        else:
            pattern = f"[network-traffic:dst_port = {item.get('port', 80)}]"

        stix_objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": f"{item.get('threat', 'THREAT')} Indicator ({item.get('ioc_id')})",
            "description": f"Extracted from Layer 2 Quarantine Decoy. Attacker IP: {indicator_val}. Target Port: {item.get('port')}. Severity: {item.get('severity')}. MITRE ATT&CK: {item.get('mitre')}.",
            "indicator_types": ["malicious-activity", "anomalous-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": datetime.utcnow().isoformat() + "Z",
            "confidence": item.get("confidence", 90),
            "created_by_ref": sensor_id,
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": item.get("mitre", "T1498")
                }
            ]
        })

    stix_bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": stix_objects
    }

    stix_export_path = os.path.join(DATA_DIR, "stix2_bundle_export.json")
    with open(stix_export_path, "w") as f:
        json.dump(stix_bundle, f, indent=2)
    print(f"[+] Standardized STIX 2.1 Threat Intel Bundle saved to: {stix_export_path}")

    # 4. Print Summary Terminal Table
    print("\n" + "=" * 95)
    print(f"{'IOC ID':<10} | {'TYPE':<8} | {'INDICATOR':<35} | {'THREAT':<18} | {'SEVERITY':<10} | {'CONF'}")
    print("=" * 95)
    for item in iocs:
        ind_str = str(item.get('indicator'))[:34]
        print(f"{item.get('ioc_id'):<10} | {item.get('type'):<8} | {ind_str:<35} | {item.get('threat'):<18} | {item.get('severity'):<10} | {item.get('confidence')}%")
    print("=" * 95)

    print("\n" + "=" * 95)
    print(f"{'SESSION ID':<13} | {'ATTACKER IP':<16} | {'PORT':<6} | {'ATTACK TYPE':<18} | {'STATUS':<12} | {'CAPTURED OPS'}")
    print("=" * 95)
    for sess in sessions:
        cmd_count = len(sess.get('captured_commands', []))
        print(f"{sess.get('session_id'):<13} | {sess.get('attacker_ip'):<16} | {sess.get('target_port'):<6} | {sess.get('attack_type'):<18} | {sess.get('status'):<12} | {cmd_count} entries")
    print("=" * 95)

if __name__ == "__main__":
    export_all()
