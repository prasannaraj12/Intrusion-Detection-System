"""
Sample PCAP Generator for AegisNIDS Testing & Validation.
Generates genuine PCAP binary files using Scapy with realistic network traffic:
- Benign HTTPS/DNS web browsing
- DDoS SYN flood attack
- Multi-port reconnaissance scan
- Slowloris persistent socket exhaustion
"""
import os
import random
import time
from scapy.all import wrpcap, Ether, IP, TCP, UDP

def create_sample_pcaps(output_dir="app/data/pcaps"):
    os.makedirs(output_dir, exist_ok=True)
    base_time = 1791234567.0  # reference epoch
    
    # 1. Benign HTTPS & DNS Traffic (sample_benign.pcap)
    benign_pkts = []
    t = base_time
    client_ip = "192.168.1.105"
    server_ip = "93.184.216.34"  # example.com
    dns_server = "8.8.8.8"
    client_port = 54321
    
    # DNS Query & Response
    dns_q = Ether()/IP(src=client_ip, dst=dns_server)/UDP(sport=client_port, dport=53)
    dns_q.time = t
    benign_pkts.append(dns_q)
    t += 0.024
    dns_r = Ether()/IP(src=dns_server, dst=client_ip)/UDP(sport=53, dport=client_port)
    dns_r.time = t
    benign_pkts.append(dns_r)
    
    # TLS 3-Way Handshake + Data
    t += 0.015
    syn = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=443, flags='S')
    syn.time = t
    benign_pkts.append(syn)
    t += 0.032
    syn_ack = Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=443, dport=client_port, flags='SA')
    syn_ack.time = t
    benign_pkts.append(syn_ack)
    t += 0.001
    ack = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=443, flags='A')
    ack.time = t
    benign_pkts.append(ack)
    
    # Subsequent HTTP data exchange
    for i in range(12):
        t += random.uniform(0.015, 0.095)
        is_fwd = (i % 2 == 0)
        p = Ether()/IP(src=client_ip if is_fwd else server_ip, dst=server_ip if is_fwd else client_ip)/\
            TCP(sport=client_port if is_fwd else 443, dport=443 if is_fwd else client_port, flags='PA')
        p.time = t
        benign_pkts.append(p)
        
    benign_path = os.path.join(output_dir, "sample_benign.pcap")
    wrpcap(benign_path, benign_pkts)
    
    # 2. DDoS SYN Flood Traffic (sample_ddos.pcap)
    ddos_pkts = []
    t = base_time
    attacker_ip = "203.0.113.42"
    target_ip = "10.0.0.1"
    attack_port = 55443
    
    # High-intensity sub-millisecond SYN burst on a flow
    for i in range(50):
        t += random.uniform(0.00015, 0.00085)  # rapid sub-millisecond flood (150us - 850us)
        p = Ether()/IP(src=attacker_ip, dst=target_ip)/TCP(sport=attack_port, dport=80, flags='S')
        p.time = t
        ddos_pkts.append(p)
        
    ddos_path = os.path.join(output_dir, "sample_ddos.pcap")
    wrpcap(ddos_path, ddos_pkts)
    
    # 3. Port Scan Reconnaissance (sample_portscan.pcap)
    scan_pkts = []
    t = base_time
    scanner_ip = "198.51.100.88"
    scan_sport = 49152
    ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080]
    
    for p in ports_to_scan:
        for attempt in range(2):
            t += random.uniform(0.0007, 0.0025)
            pkt = Ether()/IP(src=scanner_ip, dst=target_ip)/TCP(sport=scan_sport, dport=p, flags='S')
            pkt.time = t
            scan_pkts.append(pkt)
        
    scan_path = os.path.join(output_dir, "sample_portscan.pcap")
    wrpcap(scan_path, scan_pkts)
    
    # 4. Mixed Traffic Capture (sample_mixed.pcap)
    mixed_path = os.path.join(output_dir, "sample_mixed.pcap")
    wrpcap(mixed_path, sorted(benign_pkts + ddos_pkts + scan_pkts, key=lambda p: float(p.time)))
    
    print(f"Generated sample PCAPs in {output_dir}:")
    print(f"  - {benign_path} ({len(benign_pkts)} packets)")
    print(f"  - {ddos_path} ({len(ddos_pkts)} packets)")
    print(f"  - {scan_path} ({len(scan_pkts)} packets)")
    print(f"  - {mixed_path} ({len(benign_pkts) + len(ddos_pkts) + len(scan_pkts)} packets)")
    return [benign_path, ddos_path, scan_path, mixed_path]

if __name__ == '__main__':
    create_sample_pcaps()
