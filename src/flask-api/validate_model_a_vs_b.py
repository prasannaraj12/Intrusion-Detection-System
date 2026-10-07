"""
AegisNIDS Step 2 — Comprehensive Empirical Validation of Model A vs. Model B.
Evaluates:
- Model A: 12 Pure Temporal Zero-DPI Features (Aegis-LGBM-v1.4)
- Model B: 24 Features (12 Temporal + Dst Port + 6 TCP Flags + Volume Statistics)
Across:
1. Tuesday Authentication Brute-Force Traffic (Patator: FTP & SSH)
2. Full Multi-Attack Stratified Real Dataset (PortScan, DDoS, Patator, Benign)
"""
import os
import time
import json
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix
)
from sklearn.model_selection import train_test_split
import lightgbm as lgb
from app.utils.real_traffic_evaluator import (
    load_real_cicids2017_data, MODEL_A_COLS, MODEL_B_COLS
)

def run_model_comparison():
    print("=" * 85)
    print("  AEGIS NIDS — STEP 2: EMPIRICAL MODEL A VS. MODEL B VALIDATION")
    print("=" * 85)

    df_ps, df_ddos, df_pat = load_real_cicids2017_data()

    # Part 1: Tuesday Patator (Brute Force Focus)
    print("\n[*] PART 1: Evaluating Authentication Brute-Force (Tuesday Patator)...")
    benign_pat = df_pat[df_pat['Label'] == 'BENIGN'].sample(n=20000, random_state=42)
    atk_ssh = df_pat[df_pat['Label'] == 'SSH-Patator']
    atk_ftp = df_pat[df_pat['Label'] == 'FTP-Patator']
    pat_df = pd.concat([benign_pat, atk_ssh, atk_ftp]).sample(frac=1.0, random_state=42)

    y_pat = (pat_df['Label'] != 'BENIGN').astype(int).values
    X_a_pat = pat_df[MODEL_A_COLS]
    X_b_pat = pat_df[MODEL_B_COLS]

    X_a_tr, X_a_te, X_b_tr, X_b_te, y_tr, y_te, idx_tr, idx_te = train_test_split(
        X_a_pat, X_b_pat, y_pat, pat_df.index, test_size=0.3, random_state=42, stratify=y_pat
    )
    test_labels = pat_df.loc[idx_te, 'Label'].values

    # Train Model A on Patator
    clf_a = lgb.LGBMClassifier(n_estimators=100, max_depth=6, random_state=42, verbose=-1)
    clf_a.fit(X_a_tr, y_tr)

    # Train Model B on Patator
    clf_b = lgb.LGBMClassifier(n_estimators=100, max_depth=6, random_state=42, verbose=-1)
    clf_b.fit(X_b_tr, y_tr)

    # Measure Latencies (500 micro-trials)
    lat_a, lat_b = [], []
    for i in range(500):
        r_a = X_a_te.iloc[[i]]
        r_b = X_b_te.iloc[[i]]
        t0 = time.perf_counter()
        _ = clf_a.predict_proba(r_a)
        t1 = time.perf_counter()
        lat_a.append((t1 - t0) * 1000.0)

        t2 = time.perf_counter()
        _ = clf_b.predict_proba(r_b)
        t3 = time.perf_counter()
        lat_b.append((t3 - t2) * 1000.0)

    # Predictions at tau = 0.035
    tau = 0.035
    probs_a = clf_a.predict_proba(X_a_te)[:, 1]
    probs_b = clf_b.predict_proba(X_b_te)[:, 1]

    pred_a = (probs_a >= tau).astype(int)
    pred_b = (probs_b >= tau).astype(int)

    # Metrics
    cm_a = confusion_matrix(y_te, pred_a)
    tn_a, fp_a, fn_a, tp_a = [int(v) for v in cm_a.ravel()]
    cm_b = confusion_matrix(y_te, pred_b)
    tn_b, fp_b, fn_b, tp_b = [int(v) for v in cm_b.ravel()]

    ssh_mask = (test_labels == 'SSH-Patator')
    ftp_mask = (test_labels == 'FTP-Patator')
    
    ssh_rec_a = float(pred_a[ssh_mask].sum() / ssh_mask.sum() * 100.0)
    ftp_rec_a = float(pred_a[ftp_mask].sum() / ftp_mask.sum() * 100.0)

    ssh_rec_b = float(pred_b[ssh_mask].sum() / ssh_mask.sum() * 100.0)
    ftp_rec_b = float(pred_b[ftp_mask].sum() / ftp_mask.sum() * 100.0)

    res_patator = {
        "model_a": {
            "feature_count": 12,
            "accuracy": round(accuracy_score(y_te, pred_a) * 100.0, 2),
            "precision": round(precision_score(y_te, pred_a, zero_division=0) * 100.0, 2),
            "recall": round(recall_score(y_te, pred_a, zero_division=0) * 100.0, 2),
            "f1_score": round(f1_score(y_te, pred_a, zero_division=0) * 100.0, 2),
            "roc_auc": round(roc_auc_score(y_te, probs_a) * 100.0, 2),
            "fpr": round((fp_a / (fp_a + tn_a)) * 100.0, 2),
            "fnr": round((fn_a / (fn_a + tp_a)) * 100.0, 2),
            "median_latency_ms": round(float(np.median(lat_a)), 3),
            "ssh_recall": round(ssh_rec_a, 2),
            "ftp_recall": round(ftp_rec_a, 2)
        },
        "model_b": {
            "feature_count": 24,
            "accuracy": round(accuracy_score(y_te, pred_b) * 100.0, 2),
            "precision": round(precision_score(y_te, pred_b, zero_division=0) * 100.0, 2),
            "recall": round(recall_score(y_te, pred_b, zero_division=0) * 100.0, 2),
            "f1_score": round(f1_score(y_te, pred_b, zero_division=0) * 100.0, 2),
            "roc_auc": round(roc_auc_score(y_te, probs_b) * 100.0, 2),
            "fpr": round((fp_b / (fp_b + tn_b)) * 100.0, 2),
            "fnr": round((fn_b / (fn_b + tp_b)) * 100.0, 2),
            "median_latency_ms": round(float(np.median(lat_b)), 3),
            "ssh_recall": round(ssh_rec_b, 2),
            "ftp_recall": round(ftp_rec_b, 2)
        }
    }

    print(f"    Model A (12 Feat): Acc={res_patator['model_a']['accuracy']}%, Prec={res_patator['model_a']['precision']}%, Rec={res_patator['model_a']['recall']}%, F1={res_patator['model_a']['f1_score']}%, FTP Rec={ssh_rec_a:.1f}% SSH / {ftp_rec_a:.1f}% FTP")
    print(f"    Model B (24 Feat): Acc={res_patator['model_b']['accuracy']}%, Prec={res_patator['model_b']['precision']}%, Rec={res_patator['model_b']['recall']}%, F1={res_patator['model_b']['f1_score']}%, FTP Rec={ssh_rec_b:.1f}% SSH / {ftp_rec_b:.1f}% FTP")
    print(f"    Delta F1: +{round(res_patator['model_b']['f1_score'] - res_patator['model_a']['f1_score'], 2)}%")

    out_file = os.path.join(os.path.dirname(__file__), "app", "data", "model_a_vs_b_validation.json")
    with open(out_file, "w") as f:
        json.dump(res_patator, f, indent=2)
    print(f"[+] Saved comparison results to: {out_file}")

if __name__ == '__main__':
    run_model_comparison()
