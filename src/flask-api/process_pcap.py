#!/usr/bin/env python3
"""
AegisNIDS Command-Line PCAP Processing & Forensic Analysis Utility.
Parses packet capture files, reconstructs flows, extracts temporal features,
and executes real-time AI intrusion detection with TreeSHAP explanations.

Usage:
    python process_pcap.py --input traffic.pcap
    python process_pcap.py --input traffic.pcap --threshold 0.035 --output report.json --summary
"""
import sys
import os
import argparse
import json
import pickle

from config import Config
from app.utils.pcap_processor import process_pcap_file

def main():
    parser = argparse.ArgumentParser(
        description="AegisNIDS — PCAP Flow Reconstruction & Threat Analysis CLI"
    )
    parser.add_argument(
        "--input", "-i",
        required=True,
        help="Path to the PCAP/PCAPNG capture file"
    )
    parser.add_argument(
        "--threshold", "-t",
        type=float,
        default=0.035,
        help="Decision threshold for attack classification (default: 0.035 calibrated)"
    )
    parser.add_argument(
        "--model", "-m",
        default=Config.MODEL_PATH,
        help=f"Path to trained LightGBM model (default: {Config.MODEL_PATH})"
    )
    parser.add_argument(
        "--output", "-o",
        help="Path to save full JSON analysis report"
    )
    parser.add_argument(
        "--no-quarantine",
        action="store_true",
        help="Disable automatic quarantine to Layer 2 honeypot vault"
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        default=True,
        help="Print formatted terminal forensic table (default: True)"
    )
    
    args = parser.parse_args()
    
    if not os.path.exists(args.input):
        print(f"Error: PCAP input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)
        
    print("=" * 80)
    print("  AEGIS NIDS — PCAP FLOW RECONSTRUCTION & AI DETECTION ENGINE")
    print("=" * 80)
    print(f"[*] Loading model from: {args.model}")
    with open(args.model, 'rb') as f:
        model = pickle.load(f)
        
    print(f"[*] Ingesting & reconstructing flows from: {args.input}")
    print(f"[*] Classification threshold: {args.threshold} (Calibrated Zero-DPI boundary)")
    
    results = process_pcap_file(
        pcap_path=args.input,
        model=model,
        threshold=args.threshold,
        quarantine_high_risk=(not args.no_quarantine)
    )
    
    # Print formatted summary table
    print("\n" + "-" * 80)
    print(f"  ANALYSIS SUMMARY: {results['pcap_file']}")
    print("-" * 80)
    print(f"  Packets Processed:    {results['total_packets_parsed']}")
    print(f"  Reconstructed Flows:  {results['reconstructed_flows']}")
    print(f"  Analyzed Flow Convs:  {results['analyzed_flows']}")
    print(f"  Threats Detected:     {results['attacks_flagged']}")
    print(f"  Benign Conversations: {results['benign_flows']}")
    print(f"  Quarantined Sessions: {results['quarantined_sessions_count']}")
    print(f"  Total Wall Time:      {results['processing_time_ms']:.2f} ms")
    print("-" * 80)
    
    if args.summary and results['flows']:
        print("\n" + "=" * 115)
        print(f"{'FLOW ID / ENDPOINTS':<35} | {'RISK':<6} | {'TIER':<10} | {'CLASSIFICATION':<18} | {'MITRE TTP':<15} | {'SHAP ROOT CAUSE'}")
        print("=" * 115)
        for f in results['flows'][:15]:  # show first 15 flows
            flow_label = f"{f['src_ip']}:{f['src_port']} -> {f['dst_ip']}:{f['dst_port']}"[:34]
            mitre_short = f['mitre_ttp'].split(' - ')[0] if ' - ' in f['mitre_ttp'] else f['mitre_ttp']
            print(f"{flow_label:<35} | {f['risk_score']:4.1f}% | {f['policy']:<10} | {f['attack_category']:<18} | {mitre_short:<15} | {f['shap_explanation'][:25]}...")
        if len(results['flows']) > 15:
            print(f"... and {len(results['flows']) - 15} additional flow conversations analyzed.")
        print("=" * 115)
        
    if args.output:
        with open(args.output, 'w') as out_f:
            json.dump(results, out_f, indent=2)
        print(f"\n[+] Full forensic JSON exported to: {args.output}")
        
    print("\n[+] PCAP pipeline execution complete.")

if __name__ == '__main__':
    main()
