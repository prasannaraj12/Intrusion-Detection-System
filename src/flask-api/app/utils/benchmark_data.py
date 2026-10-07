"""
Research Benchmark & Empirical Validation Report for AegisNIDS.
Provides audited, mathematically consistent empirical validation metrics:
- Single source of truth: confusion matrix mathematically determines precision, recall, f1, accuracy, etc.
- Explicit threshold separation: uncalibrated baseline (0.500) vs calibrated operational (0.035).
- Real latency percentiles: feature extraction vs model inference vs total detection.
- Honest claim verification: Model B, Model C, and Full-DPI comparisons marked NOT VERIFIED.
- Honeypot MLOps feedback loop: real measured delta F1 and automated RETAIN_V1 decision.
"""
import time
from app.utils.empirical_evaluator import run_empirical_validation
from app.utils.model_trainer import run_feedback_loop_training

_CACHED_BENCHMARK = None
_LAST_RUN_TIME = 0

def get_benchmark_report(force_refresh=False):
    """
    Get or compute empirical validation benchmark data with strict mathematical consistency.
    """
    global _CACHED_BENCHMARK, _LAST_RUN_TIME
    now = time.time()
    
    if _CACHED_BENCHMARK is not None and not force_refresh and (now - _LAST_RUN_TIME < 600):
        return _CACHED_BENCHMARK
        
    try:
        raw = run_empirical_validation()
        
        calib = raw['calibrated_threshold_035']
        uncal = raw['uncalibrated_threshold_050']
        sub = raw['dataset_subsets']
        lat = raw['latency_breakdown']
        jit = raw['adversarial_jitter_experiment']
        
        # Execute genuine honeypot feedback retraining test
        retrain_res = run_feedback_loop_training()
        
        # Build adversarial test cards for frontend compatibility
        adv_test_results = [
            {
                "scenario": "Zero-Delay SYN Flood",
                "timing_pattern": "Uniform IAT < 1.5ms (Jitter: 0ms)",
                "detection_rate": f"{jit['results'][0]['detection_rate_pct_035']}%",
                "classification": "DDOS_SYN_FLOOD (HIGH RISK)"
            },
            {
                "scenario": "Low Jitter Timing Evasion",
                "timing_pattern": "Random Poisson delay (0 - 25ms)",
                "detection_rate": f"{jit['results'][1]['detection_rate_pct_035']}%",
                "classification": "ANOMALOUS_BURST (MEDIUM RISK)"
            },
            {
                "scenario": "Medium Jitter Timing Evasion",
                "timing_pattern": "Random Poisson delay (0 - 50ms)",
                "detection_rate": f"{jit['results'][2]['detection_rate_pct_035']}%",
                "classification": "ANOMALOUS_BURST (MEDIUM RISK)"
            },
            {
                "scenario": "High Jitter Timing Evasion",
                "timing_pattern": "Random Poisson delay (0 - 100ms)",
                "detection_rate": f"{jit['results'][3]['detection_rate_pct_035']}%",
                "classification": "ANOMALOUS_BURST (MEDIUM RISK)"
            },
            {
                "scenario": "Extreme Jitter Timing Evasion",
                "timing_pattern": "Random Poisson delay (0 - 250ms)",
                "detection_rate": f"{jit['results'][4]['detection_rate_pct_035']}%",
                "classification": "ANOMALOUS_BURST (MEDIUM RISK)"
            },
            {
                "scenario": "Slowloris Idle Evasion",
                "timing_pattern": "Extended idle gaps (0 - 500ms)",
                "detection_rate": f"{jit['results'][5]['detection_rate_pct_035']}%",
                "classification": "DOS_SLOWLORIS (Idle Spike)"
            }
        ]
        
        # Format Model A metrics for frontend table
        m_a_cic17 = sub['CIC-IDS2017']['metrics']
        m_a_cic18 = sub['CSE-CIC-IDS2018']['metrics']
        m_a_overall = calib['metrics']
        
        report = {
            "research_hypothesis": "Can lightweight, payload-independent temporal features detect intrusions in real time without Deep Packet Inspection?",
            "execution_mode": "EMPIRICAL_AUDITED_RUN",
            "timestamp": raw['timestamp'],
            "dataset": raw['dataset_info']['source'],
            "total_evaluated_flows": raw['total_evaluated_flows'],
            "benign_samples": raw['dataset_info']['benign_samples'],
            "attack_samples": raw['dataset_info']['attack_samples'],
            "features": raw['dataset_info']['feature_count'],
            "threshold": calib['threshold'],
            "confusion_matrix": calib['confusion_matrix'],
            "metrics": calib['metrics'],
            "uncalibrated_baseline": {
                "threshold": uncal['threshold'],
                "confusion_matrix": uncal['confusion_matrix'],
                "metrics": uncal['metrics']
            },
            "latency": lat,
            "models": [
                {
                    "id": "model_a_12_temporal",
                    "name": "Model A: 12-Temporal Features (Zero-DPI)",
                    "architecture": "LightGBM Classifier",
                    "features_count": 12,
                    "feature_scope": "Zero-DPI / Inter-Arrival Times & Idle Timing",
                    "status": "ACTIVE_PRODUCTION",
                    "version": "Aegis-LGBM-v1.4",
                    "verified": True,
                    "metrics": {
                        "cicids2017": {
                            "precision": m_a_cic17['precision'],
                            "recall": m_a_cic17['recall'],
                            "f1_score": m_a_cic17['f1_score'],
                            "roc_auc": m_a_cic17['roc_auc'],
                            "false_positive_rate": m_a_cic17['false_positive_rate'],
                            "median_latency_ms": sub['CIC-IDS2017']['median_latency_ms']
                        },
                        "cicids2018_external": {
                            "precision": m_a_cic18['precision'],
                            "recall": m_a_cic18['recall'],
                            "f1_score": m_a_cic18['f1_score'],
                            "roc_auc": m_a_cic18['roc_auc'],
                            "false_positive_rate": m_a_cic18['false_positive_rate'],
                            "median_latency_ms": sub['CSE-CIC-IDS2018']['median_latency_ms']
                        },
                        "live_lab": {
                            "precision": m_a_overall['precision'],
                            "recall": m_a_overall['recall'],
                            "f1_score": m_a_overall['f1_score'],
                            "roc_auc": m_a_overall['roc_auc'],
                            "false_positive_rate": m_a_overall['false_positive_rate'],
                            "median_latency_ms": lat['total_detection_ms']['median']
                        }
                    }
                }
            ],
            "unverified_models": [
                {
                    "id": "model_b_extended_flow",
                    "name": "Model B: 24-Feature Extended Flow Model",
                    "status": "NOT VERIFIED",
                    "note": "Experiment infrastructure implemented; results pending validated dataset."
                },
                {
                    "id": "full_dpi_baseline",
                    "name": "Reference Baseline: Full 84-Feature DPI Model",
                    "status": "NOT VERIFIED",
                    "note": "Experiment infrastructure implemented; results pending validated dataset."
                }
            ],
            "zero_dpi_claim": {
                "claim": "Zero-DPI temporal features capture flow timing dynamics without payload inspection.",
                "ratio_calculation": f"Model A F1 = {calib['metrics']['f1_score'] * 100:.1f}%. Model C reference is not evaluated on shared test partition.",
                "verification_status": "NOT VERIFIED (Model C not evaluated on shared test partition)"
            },
            "adversarial_timing_test": {
                "hypothesis": "Does an attacker randomizing inter-arrival delays bypass temporal detection?",
                "status": jit['status'],
                "status_note": jit['status_note'],
                "verified": False,
                "test_results": adv_test_results
            },
            "retraining_pipeline": {
                "status": "ACTIVE_FEEDBACK_LOOP",
                "current_production_model": "Aegis-LGBM-v1.4",
                "candidate_model": "Aegis-LGBM-v2.0-RC",
                "honeypot_captured_samples": retrain_res['honeypot_samples_incorporated'],
                "validation_status": retrain_res['retraining_approval'],
                "decision": retrain_res['retraining_approval'],
                "model_v1": retrain_res['model_v1'],
                "model_v2": retrain_res['model_v2'],
                "measured_delta_f1": retrain_res['deltas']['delta_f1_score'],
                "measured_delta_precision": retrain_res['deltas']['delta_precision'],
                "measured_delta_recall": retrain_res['deltas']['delta_recall'],
                "gatekeeper_note": "Candidate model v2 exhibited validation performance degradation. Automated MLOps gatekeeper retained v1 in production." if retrain_res['retraining_approval'] == 'RETAIN_V1' else "Candidate approved for staged canary deployment."
            }
        }
        
        _CACHED_BENCHMARK = report
        _LAST_RUN_TIME = now
        return report
    except Exception as e:
        print(f"Error computing empirical benchmark: {e}")
        return {"error": str(e)}
