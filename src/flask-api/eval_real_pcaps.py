"""
Evaluation of AegisNIDS on real CIC-IDS2017 PCAP slices.
Extracts 5-tuple flows, 12 Zero-DPI temporal features, LightGBM inference, and per-flow metrics.
"""
import os
import pickle
import json
import time
from app.utils.pcap_processor import process_pcap_file, parse_pcap_to_flows
from config import Config

with open(Config.MODEL_PATH, 'rb') as f:
    model = pickle.load(f)

pcap_files = [
    'cicids2017_tuesday.pcap',
    'cicids2017_wednesday.pcap',
    'cicids2017_friday.pcap'
]

summary = {}
for fname in pcap_files:
    fpath = os.path.join('app', 'data', 'pcaps', fname)
    if not os.path.exists(fpath):
        print(f"Skipping missing file: {fpath}")
        continue
    
    t0 = time.perf_counter()
    res = process_pcap_file(
        pcap_path=fpath,
        model=model,
        threshold=0.035,
        quarantine_high_risk=False
    )
    t_elapsed = (time.perf_counter() - t0) * 1000
    
    summary[fname] = res
    print(f"=== {fname} ===")
    print(f"  File size:            {res['file_size_bytes']} bytes")
    print(f"  Packets Parsed:       {res['total_packets_parsed']}")
    print(f"  Skipped (non-IP):     {res['skipped_packets']}")
    print(f"  Reconstructed Flows:  {res['reconstructed_flows']}")
    print(f"  Analyzed Flows (>=2): {res['analyzed_flows']}")
    print(f"  Threats Flagged:      {res['attacks_flagged']}")
    print(f"  Benign Flows:         {res['benign_flows']}")
    print(f"  Processing Time:      {res['processing_time_ms']:.2f} ms")
    
    # Analyze policy breakdown
    policies = {'ALLOW': 0, 'MONITOR': 0, 'QUARANTINE': 0}
    for flow in res['flows']:
        pol = flow.get('policy', 'ALLOW')
        policies[pol] = policies.get(pol, 0) + 1
    print(f"  Policy Tiers:         {policies}")
    print()

with open('app/data/real_pcaps_eval_summary.json', 'w') as out_f:
    json.dump(summary, out_f, indent=2)
print("Saved summary to app/data/real_pcaps_eval_summary.json")
