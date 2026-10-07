"""
AegisNIDS Step 1 — Three-Tier Operational Policy Calibration on Real CIC-IDS2017.
Evaluates candidate decision boundaries:
Tier 1: ALLOW (Low Risk)
Tier 2: MONITOR (Medium Risk / Watchlist)
Tier 3: QUARANTINE (High Risk / Honeypot Sinkhole)
"""
import os
import json
import joblib
import numpy as np
import pandas as pd
from app.utils.real_traffic_evaluator import load_real_cicids2017_data, MODEL_A_COLS

def evaluate_three_tier_policies():
    print("=" * 85)
    print("  AEGIS NIDS — THREE-TIER POLICY OPERATIONAL CALIBRATION (REAL CIC-IDS2017)")
    print("=" * 85)

    df_ps, df_ddos, df_pat = load_real_cicids2017_data()

    # Stratified 20,000 real flows
    benign_ps = df_ps[df_ps['Label'] == 'BENIGN'].sample(n=3500, random_state=42)
    benign_ddos = df_ddos[df_ddos['Label'] == 'BENIGN'].sample(n=3500, random_state=42)
    benign_pat = df_pat[df_pat['Label'] == 'BENIGN'].sample(n=3000, random_state=42)
    benign_all = pd.concat([benign_ps, benign_ddos, benign_pat])

    atk_ps = df_ps[df_ps['Label'] == 'PortScan'].sample(n=3500, random_state=42)
    atk_ddos = df_ddos[df_ddos['Label'] == 'DDoS'].sample(n=3500, random_state=42)
    atk_ssh = df_pat[df_pat['Label'] == 'SSH-Patator'].sample(n=1500, random_state=42)
    atk_ftp = df_pat[df_pat['Label'] == 'FTP-Patator'].sample(n=1500, random_state=42)
    atk_all = pd.concat([atk_ps, atk_ddos, atk_ssh, atk_ftp])

    eval_df = pd.concat([benign_all, atk_all]).sample(frac=1.0, random_state=42)
    y_true = (eval_df['Label'] != 'BENIGN').astype(int).values
    X_a = eval_df[MODEL_A_COLS]

    model_path = os.path.join(os.path.dirname(__file__), "app", "models", "model.pkl")
    model_a = joblib.load(model_path)
    y_probs = model_a.predict_proba(X_a)[:, 1]

    candidates = [
        {"name": "Configuration 1 (Legacy Default)", "t_mon": 0.035, "t_quar": 0.70},
        {"name": "Configuration 2 (Noise Reduced)", "t_mon": 0.100, "t_quar": 0.70},
        {"name": "Configuration 3 (Balanced Operational - RECOMMENDED)", "t_mon": 0.200, "t_quar": 0.75},
        {"name": "Configuration 4 (Strict Quarantine)", "t_mon": 0.300, "t_quar": 0.80},
    ]

    results = []
    for cand in candidates:
        t_mon = cand["t_mon"]
        t_quar = cand["t_quar"]

        # Assign tiers
        # 0: ALLOW (< t_mon)
        # 1: MONITOR (t_mon <= p < t_quar)
        # 2: QUARANTINE (p >= t_quar)
        tiers = np.zeros(len(y_probs), dtype=int)
        tiers[(y_probs >= t_mon) & (y_probs < t_quar)] = 1
        tiers[y_probs >= t_quar] = 2

        # Breakdowns
        # ALLOW Tier
        allow_mask = (tiers == 0)
        allow_total = int(allow_mask.sum())
        allow_benign = int(((y_true == 0) & allow_mask).sum())
        allow_attacks = int(((y_true == 1) & allow_mask).sum())  # Escaped threats (False Negative to perimeter)
        allow_safety = (allow_benign / allow_total * 100.0) if allow_total > 0 else 0.0

        # MONITOR Tier
        mon_mask = (tiers == 1)
        mon_total = int(mon_mask.sum())
        mon_benign = int(((y_true == 0) & mon_mask).sum())      # Watchlist noise
        mon_attacks = int(((y_true == 1) & mon_mask).sum())     # Monitored anomalies
        mon_precision = (mon_attacks / mon_total * 100.0) if mon_total > 0 else 0.0

        # QUARANTINE Tier
        quar_mask = (tiers == 2)
        quar_total = int(quar_mask.sum())
        quar_benign = int(((y_true == 0) & quar_mask).sum())    # False quarantine (Disrupted legitimate)
        quar_attacks = int(((y_true == 1) & quar_mask).sum())   # True quarantine (Neutralized threat)
        quar_precision = (quar_attacks / quar_total * 100.0) if quar_total > 0 else 0.0
        quar_coverage = (quar_attacks / 10000 * 100.0)

        # Overall security metrics
        threat_intercept_rate = ((mon_attacks + quar_attacks) / 10000) * 100.0
        benign_pass_rate = (allow_benign / 10000) * 100.0

        cand_res = {
            "name": cand["name"],
            "threshold_monitor": t_mon,
            "threshold_quarantine": t_quar,
            "allow_tier": {
                "total": allow_total,
                "benign": allow_benign,
                "escaped_attacks": allow_attacks,
                "benign_purity_pct": round(allow_safety, 2)
            },
            "monitor_tier": {
                "total": mon_total,
                "benign_watchlist": mon_benign,
                "flagged_attacks": mon_attacks,
                "attack_precision_pct": round(mon_precision, 2)
            },
            "quarantine_tier": {
                "total": quar_total,
                "false_quarantines": quar_benign,
                "true_quarantines": quar_attacks,
                "quarantine_precision_pct": round(quar_precision, 2),
                "attack_coverage_pct": round(quar_coverage, 2)
            },
            "system_totals": {
                "threat_interception_pct": round(threat_intercept_rate, 2),
                "benign_forward_pct": round(benign_pass_rate, 2),
                "false_quarantine_rate_pct": round((quar_benign / 10000) * 100.0, 2)
            }
        }
        results.append(cand_res)

        print(f"\n--> {cand['name']} (MONITOR: {t_mon}, QUARANTINE: {t_quar}):")
        print(f"    ALLOW Tier:      {allow_total:5d} flows | {allow_benign:5d} Benign ({allow_safety:.1f}% purity) | {allow_attacks:3d} Escaped Threats")
        print(f"    MONITOR Tier:    {mon_total:5d} flows | {mon_attacks:5d} Attacks | {mon_benign:5d} Watchlist Noise ({mon_precision:.1f}% precision)")
        print(f"    QUARANTINE Tier: {quar_total:5d} flows | {quar_attacks:5d} Attacks | {quar_benign:4d} False Quarantines ({quar_precision:.2f}% precision)")
        print(f"    Summary: Threat Intercept={threat_intercept_rate:.2f}%, Benign Egress={benign_pass_rate:.2f}%, False Quarantine Rate={cand_res['system_totals']['false_quarantine_rate_pct']:.2f}%")

    out_path = os.path.join(os.path.dirname(__file__), "app", "data", "policy_tier_validation.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Saved policy tier calibration results to: {out_path}")

if __name__ == "__main__":
    evaluate_three_tier_policies()
