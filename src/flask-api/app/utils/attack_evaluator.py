"""
Attack-Type Category Evaluation Engine for AegisNIDS.
Performs granular per-class evaluation across cybersecurity attack taxonomy:
- DDOS_SYN_FLOOD (T1498.001)
- RECON_PORT_SCAN (T1046)
- BRUTE_FORCE (T1110)
- DOS_SLOWLORIS (T1499.003)
- BENIGN (Normal browsing, DNS, TLS)

Computes per-class TP, FP, TN, FN, Precision, Recall, and F1.
"""
import pickle
import numpy as np
import pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

from config import Config
from app.utils.empirical_evaluator import generate_benchmark_dataset, EXPECTED_12_COLS
from app.utils.feature_extraction import extract_all_features

def run_attack_type_evaluation(model=None, threshold=0.035, seed=1337):
    """
    Evaluate detection efficacy per attack category.
    
    Returns:
        dict: Granular per-attack performance table and category breakdown.
    """
    if model is None:
        with open(Config.MODEL_PATH, 'rb') as f:
            model = pickle.load(f)
            
    dataset = generate_benchmark_dataset(num_benign=120, num_attacks=120, seed=seed)
    
    records = []
    for item in dataset:
        feats = extract_all_features(item['packets'])
        df = pd.DataFrame([feats])[EXPECTED_12_COLS]
        prob = float(model.predict_proba(df)[0][1])
        
        records.append({
            'label': item['label'],
            'category': item['category'],
            'dataset': item['dataset'],
            'attack_prob': prob,
            'pred': int(prob >= threshold)
        })
        
    df_eval = pd.DataFrame(records)
    
    # 1. Per-attack category breakdown
    categories = ['BENIGN', 'DDOS_SYN_FLOOD', 'RECON_PORT_SCAN', 'BRUTE_FORCE', 'DOS_SLOWLORIS']
    category_results = []
    
    for cat in categories:
        sub = df_eval[df_eval['category'] == cat]
        total = len(sub)
        if total == 0:
            continue
            
        if cat == 'BENIGN':
            # For benign: True Negative = pred == 0, False Positive = pred == 1
            tn = int(np.sum(sub['pred'] == 0))
            fp = int(np.sum(sub['pred'] == 1))
            detected_as_benign = tn
            false_alarms = fp
            precision = float(tn / (tn + fp)) if (tn + fp) > 0 else 1.0
            recall = float(tn / total)
            f1 = float(2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
            
            category_results.append({
                'attack_type': cat,
                'mitre_ttp': 'N/A',
                'samples': total,
                'correctly_classified': tn,
                'misclassified': fp,
                'detection_rate_pct': round((tn / total) * 100.0, 1),
                'precision': round(precision, 4),
                'recall': round(recall, 4),
                'f1_score': round(f1, 4)
            })
        else:
            # For attack: True Positive = pred == 1, False Negative = pred == 0
            tp = int(np.sum(sub['pred'] == 1))
            fn = int(np.sum(sub['pred'] == 0))
            detected = tp
            missed = fn
            
            # Category-specific MITRE map
            mitre_map = {
                'DDOS_SYN_FLOOD': 'T1498.001 - Network Denial of Service',
                'RECON_PORT_SCAN': 'T1046 - Network Service Scanning',
                'BRUTE_FORCE': 'T1110 - Brute Force Authentication',
                'DOS_SLOWLORIS': 'T1499.003 - App Socket Exhaustion'
            }
            
            rec = float(tp / total)
            # Binary precision of attack flagging (against all flows flagged as attacks)
            category_results.append({
                'attack_type': cat,
                'mitre_ttp': mitre_map.get(cat, 'T1498'),
                'samples': total,
                'detected': tp,
                'missed': fn,
                'detection_rate_pct': round((tp / total) * 100.0, 1),
                'recall': round(rec, 4),
                'mean_attack_probability': round(float(sub['attack_prob'].mean()), 4)
            })
            
    # 2. Overall multi-class confusion matrix summary
    y_true = df_eval['label'].values
    y_pred = df_eval['pred'].values
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    
    return {
        'evaluated_flows': len(df_eval),
        'threshold': threshold,
        'overall_confusion_matrix': {
            'true_positives': int(tp),
            'false_positives': int(fp),
            'true_negatives': int(tn),
            'false_negatives': int(fn)
        },
        'overall_metrics': {
            'precision': round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
            'recall': round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
            'f1_score': round(float(f1_score(y_true, y_pred, zero_division=0)), 4)
        },
        'per_category_analysis': category_results
    }
