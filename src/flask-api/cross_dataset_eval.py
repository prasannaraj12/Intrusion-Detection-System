"""
AegisNIDS Cross-Dataset / Cross-Day Generalization Validation.
Train on Day A (Friday: DDoS & PortScan + Benign)
Evaluate on Unseen Day B (Tuesday: FTP-Patator & SSH-Patator + Benign)
Strict separation: Zero data leakage across days or attack classes.
"""
import os
import time
import json
import numpy as np
import pandas as pd
import lightgbm as lgb
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score, roc_auc_score, confusion_matrix
from app.utils.real_traffic_evaluator import load_real_cicids2017_data, MODEL_A_COLS, MODEL_B_COLS

def run_cross_day_validation():
    print("=" * 80)
    print("  AEGIS NIDS — CROSS-DAY / CROSS-DATASET VALIDATION")
    print("=" * 80)
    
    df_ps, df_ddos, df_pat = load_real_cicids2017_data()

    # Day A (Training Set: Friday PortScan + DDoS)
    print("[*] Preparing Training Set from Friday (PortScan & DDoS)...")
    train_benign = pd.concat([
        df_ps[df_ps['Label'] == 'BENIGN'].sample(n=7500, random_state=42),
        df_ddos[df_ddos['Label'] == 'BENIGN'].sample(n=7500, random_state=42)
    ])
    train_attacks = pd.concat([
        df_ps[df_ps['Label'] == 'PortScan'].sample(n=7500, random_state=42),
        df_ddos[df_ddos['Label'] == 'DDoS'].sample(n=7500, random_state=42)
    ])
    train_df = pd.concat([train_benign, train_attacks]).sample(frac=1.0, random_state=42)
    X_train_a = train_df[MODEL_A_COLS]
    y_train = (train_df['Label'] != 'BENIGN').astype(int).values

    print(f"    Training samples: {len(train_df)} flows (15,000 Benign, 15,000 Attacks: PortScan + DDoS)")

    # Train Model A on Friday
    clf_cross = lgb.LGBMClassifier(n_estimators=100, max_depth=6, random_state=42, verbose=-1)
    clf_cross.fit(X_train_a, y_train)

    # Day B (Test Set: Tuesday Patator - Completely unseen day and attack families)
    print("[*] Preparing Test Set from Tuesday (Unseen Authentication Brute-Force & Benign)...")
    test_benign = df_pat[df_pat['Label'] == 'BENIGN'].sample(n=10000, random_state=42)
    test_ssh = df_pat[df_pat['Label'] == 'SSH-Patator']
    test_ftp = df_pat[df_pat['Label'] == 'FTP-Patator']
    test_df = pd.concat([test_benign, test_ssh, test_ftp]).sample(frac=1.0, random_state=42)
    X_test_a = test_df[MODEL_A_COLS]
    y_test = (test_df['Label'] != 'BENIGN').astype(int).values

    print(f"    Test samples: {len(test_df)} flows (10,000 Benign, {len(test_ssh)} SSH-Patator, {len(test_ftp)} FTP-Patator)")

    # Evaluate zero-shot across days
    y_test_probs = clf_cross.predict_proba(X_test_a)[:, 1]
    
    # Evaluate across thresholds
    thresholds = [0.035, 0.10, 0.30, 0.50]
    results = {}
    for tau in thresholds:
        yp = (y_test_probs >= tau).astype(int)
        cm = confusion_matrix(y_test, yp)
        tn, fp, fn, tp = [int(v) for v in cm.ravel()]
        acc = float(accuracy_score(y_test, yp))
        prec = float(precision_score(y_test, yp, zero_division=0))
        rec = float(recall_score(y_test, yp, zero_division=0))
        f1 = float(f1_score(y_test, yp, zero_division=0))
        auc = float(roc_auc_score(y_test, y_test_probs))
        results[str(tau)] = {
            'threshold': tau,
            'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
            'accuracy': round(acc * 100.0, 2),
            'precision': round(prec * 100.0, 2),
            'recall': round(rec * 100.0, 2),
            'f1_score': round(f1 * 100.0, 2),
            'roc_auc': round(auc * 100.0, 2)
        }
        print(f"    --> Threshold tau = {tau}: Acc={acc*100:.2f}%, Prec={prec*100:.2f}%, Rec={rec*100:.2f}%, F1={f1*100:.2f}%, AUC={auc*100:.2f}%")

    out_file = os.path.join(os.path.dirname(__file__), "app", "data", "cross_day_validation.json")
    with open(out_file, 'w') as f:
        json.dump({
            'experiment': 'Cross-Day Zero-Shot Generalization',
            'train_dataset': 'Friday (CIC-IDS2017: PortScan + DDoS LOIC)',
            'test_dataset': 'Tuesday (CIC-IDS2017: FTP-Patator + SSH-Patator)',
            'model_architecture': 'Model A (12 Zero-DPI Temporal Features)',
            'evaluation_results': results
        }, f, indent=2)
    print(f"[+] Saved cross-day results to: {out_file}")

if __name__ == '__main__':
    run_cross_day_validation()
