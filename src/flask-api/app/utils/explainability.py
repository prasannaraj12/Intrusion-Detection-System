"""
TreeSHAP explainability engine for AegisNIDS.
Extracts exact Shapley feature attributions using LightGBM's native TreeSHAP implementation.
Answers: "Why did the AI classify this flow as an attack or benign?"
"""
import numpy as np

EXPECTED_COLS = [
    'Fwd IAT Std', 'Bwd IAT Std', 'Flow IAT Std', 'Fwd IAT Max',
    'Flow IAT Mean', 'Flow IAT Max', 'Fwd IAT Mean', 'Fwd IAT Total',
    'Flow Duration', 'Bwd IAT Max', 'Idle Max', 'Idle Mean'
]

def compute_tree_shap(model, feature_df):
    """
    Compute exact TreeSHAP feature contributions for a single flow using LightGBM booster.
    
    Args:
        model: Trained LGBMClassifier
        feature_df: pandas DataFrame containing the 12 features
        
    Returns:
        dict containing:
            - base_value: background log-odds bias
            - feature_contributions: dict of feature -> shap value
            - top_drivers: list of top features driving toward attack (+) or benign (-)
            - summary_text: plain-language explanation of the decision
    """
    try:
        booster = model.booster_
        df_ordered = feature_df[EXPECTED_COLS]
        contribs = booster.predict(df_ordered, pred_contrib=True)[0]
        
        feature_shaps = contribs[:-1]
        base_value = float(contribs[-1])
        
        # Build dictionary of feature contributions
        contributions = {}
        drivers_list = []
        for feat, val in zip(EXPECTED_COLS, feature_shaps):
            shap_val = float(val)
            feat_val = float(df_ordered[feat].iloc[0])
            contributions[feat] = {
                'shap_value': round(shap_val, 4),
                'feature_value': round(feat_val, 2),
                'direction': 'ATTACK' if shap_val > 0 else 'BENIGN',
                'impact': abs(round(shap_val, 4))
            }
            drivers_list.append({
                'feature': feat,
                'shap_value': round(shap_val, 4),
                'feature_value': round(feat_val, 2),
                'direction': 'ATTACK' if shap_val > 0 else 'BENIGN',
                'impact': abs(round(shap_val, 4))
            })
            
        # Sort by absolute impact
        drivers_list.sort(key=lambda x: x['impact'], reverse=True)
        top_drivers = drivers_list[:4]
        
        # Generate human-readable explanation
        attack_drivers = [d for d in drivers_list if d['shap_value'] > 0][:2]
        benign_drivers = [d for d in drivers_list if d['shap_value'] < 0][:2]
        
        if attack_drivers:
            primary_reason = f"Flagged primarily due to abnormal {attack_drivers[0]['feature']} (+{attack_drivers[0]['shap_value']})"
            if len(attack_drivers) > 1:
                primary_reason += f" and elevated {attack_drivers[1]['feature']} (+{attack_drivers[1]['shap_value']})"
        else:
            primary_reason = f"Normal temporal profile confirmed by standard {benign_drivers[0]['feature']} ({benign_drivers[0]['shap_value']})"
            
        return {
            'base_value': round(base_value, 4),
            'contributions': contributions,
            'top_drivers': top_drivers,
            'explanation': primary_reason
        }
    except Exception as e:
        # Fallback if booster is unavailable
        return {
            'base_value': 0.0,
            'contributions': {},
            'top_drivers': [],
            'explanation': f"SHAP calculation error: {str(e)}"
        }
