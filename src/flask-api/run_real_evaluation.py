"""
AegisNIDS — Real-Traffic Empirical Evaluation CLI
Executes full validation on 20,000 real network flows from CIC-IDS2017
and evaluates Model B on authentication brute-force traffic.

Usage:
    python run_real_evaluation.py
    python run_real_evaluation.py --threshold 0.035 --refresh
"""

import sys
import os
import argparse

# Add flask-api to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.utils.real_traffic_evaluator import run_real_cicids2017_evaluation

def main():
    parser = argparse.ArgumentParser(description="AegisNIDS Real CIC-IDS2017 Evaluation Suite")
    parser.add_argument("--threshold", type=float, default=0.035, help="Detection threshold (default: 0.035)")
    parser.add_argument("--refresh", action="store_true", help="Force re-evaluation instead of reading cache")
    args = parser.parse_args()

    print("=" * 80)
    print("  AEGIS NIDS — REAL CIC-IDS2017 EMPIRICAL TRAFFIC VALIDATION")
    print("=" * 80)
    print(f"[*] Dataset: Canadian Institute for Cybersecurity (CIC-IDS2017)")
    print(f"[*] Operating Threshold: {args.threshold} (Calibrated Zero-DPI Boundary)")
    print(f"[*] Loading real flows from Friday PortScan, Friday DDoS, Tuesday Patator...")

    res = run_real_cicids2017_evaluation(threshold=args.threshold, force_refresh=args.refresh)
    m = res['metrics']
    cm = res['confusion_matrix']

    print("\n" + "-" * 80)
    print("  EMPIRICAL EVALUATION METRICS (20,000 REAL NETWORK FLOWS)")
    print("-" * 80)
    print(f"  Total Network Flows Evaluated: {res['total_flows']:,} (10,000 Benign, 10,000 Malicious)")
    print(f"  True Positives (TP):          {cm['tp']:,} / 10,000")
    print(f"  False Positives (FP):         {cm['fp']:,} / 10,000")
    print(f"  True Negatives (TN):          {cm['tn']:,} / 10,000")
    print(f"  False Negatives (FN):         {cm['fn']:,} / 10,000 (Missed attacks)")
    print("-" * 80)
    print(f"  Accuracy:                     {m['accuracy']}%")
    print(f"  Precision:                    {m['precision']}%")
    print(f"  Recall (Sensitivity):         {m['recall']}%  [Missed Attack Rate (FNR): {m['fnr']}%]")
    print(f"  F1-Score:                     {m['f1_score']}%")
    print(f"  ROC-AUC:                      {m['roc_auc']}%")
    print(f"  False Positive Rate (FPR):    {m['fpr']}%")
    print(f"  Per-Flow Inference Latency:   {m['inference_latency_ms']:.3f} ms")
    print("-" * 80)

    print("\n" + "=" * 80)
    print("  PER-ATTACK CATEGORY BREAKDOWN (REAL CIC-IDS2017 TRAFFIC)")
    print("=" * 80)
    print(f"{'Attack Category':<16} | {'Samples':<8} | {'Detected':<10} | {'Missed':<8} | {'Recall':<8} | {'F1-Score'}")
    print("-" * 80)
    for cat in res['per_attack_categories']:
        print(f"{cat['category']:<16} | {cat['samples']:<8} | {cat['detected']:<10} | {cat['missed']:<8} | {cat['rate']:<6.2f}%  | {cat['f1']:<6.2f}%")
    print("-" * 80)

    b = res['model_b_comparison']
    print("\n" + "=" * 80)
    print("  MODEL A vs MODEL B: RESOLVING THE BRUTE-FORCE LIMITATION")
    print("=" * 80)
    print(f"  Model A (12 Temporal Features):")
    print(f"    - Precision: {b['model_a']['precision']}% | Recall: {b['model_a']['recall']}% | F1: {b['model_a']['f1']}%")
    print(f"    - SSH Recall: {b['model_a']['ssh_recall']}% | FTP Recall: {b['model_a']['ftp_recall']}%")
    print(f"    - Finding: {b['model_a']['limitation']}")
    print()
    print(f"  Model B (24 Features: + Destination Port + 6 TCP Flags + Packet Volume):")
    print(f"    - Precision: {b['model_b']['precision']}% | Recall: {b['model_b']['recall']}% | F1: {b['model_b']['f1']}%")
    print(f"    - SSH Recall: {b['model_b']['ssh_recall']}% | FTP Recall: {b['model_b']['ftp_recall']}%")
    print(f"    - Benefit: {b['model_b']['benefit']}")
    print(f"    - Empirical Delta F1 Gain: +{b['delta_f1']}%")
    print("=" * 80)
    print("\n[+] Real CIC-IDS2017 evaluation complete. Results verified & cached.")

if __name__ == "__main__":
    main()
