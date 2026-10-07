"""
Production PCAP Ingestion & Flow Reconstruction Engine for AegisNIDS.
Parses raw PCAP/PCAPNG packet traces, reconstructs bidirectional 5-tuple flows,
extracts 12 Zero-DPI temporal features, and executes full Aegis ML detection.

Pipeline:
Raw PCAP -> Scapy Packet Parsing -> Bidirectional Flow Builder ->
12 Temporal Features -> LightGBM -> Risk Score -> TreeSHAP -> Policy Engine -> Honeypot
"""
import os
import time
from datetime import datetime
import pandas as pd
from scapy.all import rdpcap, PcapReader, IP, IPv6, TCP, UDP

from config import Config
from app.utils.feature_extraction import extract_all_features
from app.utils.explainability import compute_tree_shap
from app.utils.policy_engine import evaluate_policy
from app.utils.honeypot_ioc import record_honeypot_quarantine

EXPECTED_12_COLS = [
    'Fwd IAT Std', 'Bwd IAT Std', 'Flow IAT Std', 'Fwd IAT Max',
    'Flow IAT Mean', 'Flow IAT Max', 'Fwd IAT Mean', 'Fwd IAT Total',
    'Flow Duration', 'Bwd IAT Max', 'Idle Max', 'Idle Mean'
]

def parse_pcap_to_flows(pcap_path, idle_timeout_sec=5.0, max_packets=50000):
    """
    Parse a PCAP file and reconstruct bidirectional IP flows based on 5-tuple.
    
    Args:
        pcap_path (str): Path to PCAP file
        idle_timeout_sec (float): Gap in seconds to split a flow
        max_packets (int): Maximum packets to process for memory protection
        
    Returns:
        dict: Mapping of flow_key -> list of packet dicts
    """
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
        
    flows = {}
    packet_count = 0
    skipped_count = 0
    
    # Use PcapReader for memory-efficient streaming
    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            packet_count += 1
            if packet_count > max_packets:
                break
                
            # Filter for IP/IPv6 packets with TCP or UDP transport
            if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
                skipped_count += 1
                continue
                
            is_ipv6 = pkt.haslayer(IPv6)
            ip_layer = pkt[IPv6] if is_ipv6 else pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            
            src_port = 0
            dst_port = 0
            proto = "OTHER"
            
            if pkt.haslayer(TCP):
                src_port = int(pkt[TCP].sport)
                dst_port = int(pkt[TCP].dport)
                proto = "TCP"
            elif pkt.haslayer(UDP):
                src_port = int(pkt[UDP].sport)
                dst_port = int(pkt[UDP].dport)
                proto = "UDP"
            else:
                proto = str(ip_layer.proto if not is_ipv6 else ip_layer.nh)
                
            # Floating-point epoch timestamp from pcap
            pkt_time = float(pkt.time)
            dt = datetime.fromtimestamp(pkt_time)
            ts_iso = dt.isoformat()
            
            pkt_dict = {
                'timestamp': ts_iso,
                'epoch_time': pkt_time,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'proto': proto,
                'size': len(pkt)
            }
            
            # Canonical bidirectional flow key (sorted endpoint tuple)
            endpoint_a = (src_ip, src_port)
            endpoint_b = (dst_ip, dst_port)
            if endpoint_a <= endpoint_b:
                canonical_key = f"{src_ip}:{src_port}<->{dst_ip}:{dst_port}_{proto}"
            else:
                canonical_key = f"{dst_ip}:{dst_port}<->{src_ip}:{src_port}_{proto}"
                
            # Check for idle timeout gap to split flow if needed
            if canonical_key in flows:
                last_pkt_time = flows[canonical_key][-1]['epoch_time']
                if (pkt_time - last_pkt_time) > idle_timeout_sec:
                    # New sub-flow segment
                    canonical_key = f"{canonical_key}_seg_{int(pkt_time)}"
                    
            if canonical_key not in flows:
                flows[canonical_key] = []
            flows[canonical_key].append(pkt_dict)
            
    return flows, packet_count, skipped_count

def process_pcap_file(pcap_path, model, threshold=0.035, quarantine_high_risk=True):
    """
    Complete end-to-end processing of a PCAP file through AegisNIDS.
    
    Returns:
        dict: Detailed forensic results, flow records, detected threats, and summary metrics.
    """
    t0 = time.perf_counter()
    flows_dict, total_pkts, skipped_pkts = parse_pcap_to_flows(pcap_path)
    t1 = time.perf_counter()
    
    flow_results = []
    attacks_detected = 0
    quarantined_sessions = []
    
    for flow_id, pkts in flows_dict.items():
        if len(pkts) < 2:
            # Need at least 2 packets to compute temporal inter-arrival intervals
            continue
            
        t_f0 = time.perf_counter()
        features = extract_all_features(pkts)
        t_f1 = time.perf_counter()
        
        feature_df = pd.DataFrame([features])[EXPECTED_12_COLS]
        probs = model.predict_proba(feature_df)[0]
        attack_prob = float(probs[1])
        t_f2 = time.perf_counter()
        
        shap_data = compute_tree_shap(model, feature_df)
        policy_data = evaluate_policy(attack_prob, features, pkts)
        
        is_attack = bool(attack_prob >= threshold)
        if is_attack:
            attacks_detected += 1
            
        honeypot_session_id = None
        if policy_data['policy'] == 'QUARANTINE' and quarantine_high_risk:
            h_res = record_honeypot_quarantine({
                'src_ip': pkts[0]['src_ip'],
                'dst_ip': pkts[0]['dst_ip'],
                'port': pkts[0]['dst_port'],
                'packet_count': len(pkts),
                'risk_score': policy_data['risk_score'],
                'attack_category': policy_data['attack_category'],
                'mitre_ttp': policy_data['mitre_ttp'],
                'pcap_source': os.path.basename(pcap_path)
            })
            honeypot_session_id = h_res.get('session_id')
            quarantined_sessions.append(h_res)
            
        flow_results.append({
            'flow_id': flow_id,
            'src_ip': pkts[0]['src_ip'],
            'dst_ip': pkts[0]['dst_ip'],
            'src_port': pkts[0]['src_port'],
            'dst_port': pkts[0]['dst_port'],
            'proto': pkts[0]['proto'],
            'packet_count': len(pkts),
            'flow_duration_us': features['Flow Duration'],
            'attack_probability': round(attack_prob, 4),
            'risk_score': policy_data['risk_score'],
            'risk_level': policy_data['risk_level'],
            'policy': policy_data['policy'],
            'policy_action': policy_data['policy_action'],
            'attack_category': policy_data['attack_category'],
            'mitre_ttp': policy_data['mitre_ttp'],
            'shap_explanation': shap_data['explanation'],
            'top_drivers': shap_data['top_drivers'][:3],
            'features': features,
            'honeypot_session': honeypot_session_id,
            'timing_ms': {
                'feature_extraction': round((t_f1 - t_f0) * 1000.0, 3),
                'model_inference': round((t_f2 - t_f1) * 1000.0, 3),
                'total': round((t_f2 - t_f0) * 1000.0, 3)
            }
        })
        
    t_end = time.perf_counter()
    total_time_ms = (t_end - t0) * 1000.0
    
    return {
        'pcap_file': os.path.basename(pcap_path),
        'file_size_bytes': os.path.getsize(pcap_path),
        'total_packets_parsed': total_pkts,
        'skipped_packets': skipped_pkts,
        'reconstructed_flows': len(flows_dict),
        'analyzed_flows': len(flow_results),
        'attacks_flagged': attacks_detected,
        'benign_flows': len(flow_results) - attacks_detected,
        'quarantined_sessions_count': len(quarantined_sessions),
        'processing_time_ms': round(total_time_ms, 2),
        'flows': flow_results
    }
