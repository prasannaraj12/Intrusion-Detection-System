"""
AegisNIDS Phase 3 — Controlled Honeypot & STIX Provenance Integration Test.
Generates safe, isolated test traffic (RFC 5737 TEST-NET-1 IP: 192.0.2.77)
against the local daemon, demonstrating the full closed-loop chain:
Controlled Test Traffic -> AegisNIDS -> HIGH RISK -> Honeypot ->
Session Created -> Telemetry Captured -> IOC Generated -> STIX Export.
"""
import sys
import os
import json
import urllib.request
import urllib.parse
from datetime import datetime, timedelta
import random

API_BASE = "http://127.0.0.1:5000"
CONTROLLED_TEST_IP = "192.0.2.77"  # RFC 5737 non-routable documentation address

def run_controlled_honeypot_test():
    print("=" * 80)
    print("  AEGIS NIDS — PHASE 3: CONTROLLED LOCAL HONEYPOT PROVENANCE TEST")
    print("=" * 80)
    print(f"[*] Controlled Isolated Test Source IP: {CONTROLLED_TEST_IP} (TEST-NET-1)")
    print(f"[*] Target Endpoint: {API_BASE}/predict")

    # [1] Generate high-intensity test packets (triggering HIGH RISK >= 70.0)
    random.seed(42)
    base_time = datetime.utcnow() - timedelta(seconds=5)
    packets = []
    cur_time = base_time
    count = 28
    for i in range(count):
        cur_time += timedelta(microseconds=random.randint(100, 850))
        packets.append({
            "timestamp": cur_time.isoformat(),
            "src_ip": CONTROLLED_TEST_IP,
            "dst_ip": "10.0.0.1",
            "src_port": 54321,
            "dst_port": 80
        })

    # [2] POST packets to /predict
    post_data = json.dumps(packets).encode('utf-8')
    req = urllib.request.Request(
        f"{API_BASE}/predict",
        data=post_data,
        headers={"Content-Type": "application/json"}
    )
    resp = urllib.request.urlopen(req, timeout=5)
    assert resp.status == 200, f"Expected HTTP 200, got {resp.status}"
    pred_res = json.loads(resp.read().decode('utf-8'))
    
    risk_score = pred_res.get('risk_score', 0)
    policy = pred_res.get('policy')
    honeypot_session_id = pred_res.get('honeypot_session')
    
    print(f"[+] Prediction Result: Risk Score = {risk_score}% | Policy = {policy} | Honeypot Session = {honeypot_session_id}")
    assert risk_score >= 70.0, f"Expected risk_score >= 70.0, got {risk_score}"
    assert policy == "QUARANTINE", f"Expected policy QUARANTINE, got {policy}"
    assert honeypot_session_id is not None, "Expected honeypot_session ID in response, got None"
    print("    [PASS] Step 1: Controlled test traffic correctly triggered HIGH RISK QUARANTINE.")

    # [3] Verify session in /api/honeypot/sessions
    req_sess = urllib.request.urlopen(f"{API_BASE}/api/honeypot/sessions", timeout=5)
    assert req_sess.status == 200
    sess_data = json.loads(req_sess.read().decode('utf-8'))
    
    matching_session = None
    for s in sess_data.get('sessions', []):
        if s.get('attacker_ip') == CONTROLLED_TEST_IP and s.get('status') == 'QUARANTINED':
            matching_session = s
            break
            
    assert matching_session is not None, f"No quarantined session found for test IP {CONTROLLED_TEST_IP}"
    print(f"[+] Verified Live Honeypot Session: {matching_session['session_id']}")
    print(f"    - Attacker IP: {matching_session['attacker_ip']}")
    print(f"    - Attack Type: {matching_session['attack_type']}")
    print(f"    - Captured Telemetry: {len(matching_session['captured_commands'])} log entries")
    print("    [PASS] Step 2: Session created in Layer 2 Honeypot memory & disk vault.")

    # [4] Verify IOC generation in /api/iocs
    req_iocs = urllib.request.urlopen(f"{API_BASE}/api/iocs", timeout=5)
    assert req_iocs.status == 200
    iocs_data = json.loads(req_iocs.read().decode('utf-8'))
    
    matching_ioc = None
    for ioc in iocs_data.get('iocs', []):
        if ioc.get('indicator') == CONTROLLED_TEST_IP:
            matching_ioc = ioc
            break
            
    assert matching_ioc is not None, f"No IOC generated for test IP {CONTROLLED_TEST_IP}"
    print(f"[+] Verified Live Generated IOC: {matching_ioc['ioc_id']}")
    print(f"    - Indicator: {matching_ioc['indicator']}")
    print(f"    - Threat: {matching_ioc['threat']}")
    print(f"    - Severity: {matching_ioc['severity']}")
    print(f"    - Confidence: {matching_ioc['confidence']}%")
    print("    [PASS] Step 3: IOC successfully extracted and cataloged in IOC database.")

    # [5] Trigger STIX 2.1 Export & Validate updated bundle
    from export_threat_intel import export_all
    export_all()

    stix_bundle_path = os.path.join(os.path.dirname(__file__), "app", "data", "stix2_bundle_export.json")
    with open(stix_bundle_path, 'r', encoding='utf-8') as f:
        stix_bundle = json.load(f)

    stix_patterns = [
        obj.get('pattern') for obj in stix_bundle.get('objects', []) if obj.get('type') == 'indicator'
    ]
    expected_pattern = f"[ipv4-addr:value = '{CONTROLLED_TEST_IP}']"
    assert expected_pattern in stix_patterns, f"Expected pattern '{expected_pattern}' not found in STIX bundle: {stix_patterns}"
    print(f"[+] Verified STIX 2.1 Indicator Pattern Present: {expected_pattern}")
    print("    [PASS] Step 4: Test IOC successfully compiled into STIX 2.1 bundle.")

    # [6] Run automated STIX schema verification
    from test_stix_export import test_stix_export
    test_stix_export()
    print("    [PASS] Step 5: Updated STIX 2.1 bundle passed complete schema verification.")

    print("\n" + "=" * 80)
    print("  CONTROLLED HONEYPOT TEST COMPLETED SUCCESSFULLY WITH ZERO ERRORS!")
    print("=" * 80)

if __name__ == '__main__':
    run_controlled_honeypot_test()
