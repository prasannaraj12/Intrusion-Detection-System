"""
Upgraded API routes for AegisNIDS.
Includes 3-tier Risk Scoring, Policy Engine, TreeSHAP Explainability,
Honeypot Forensic Capture, IOC Extraction, Model Drift Monitoring, and Benchmark endpoints.
"""
from flask import Blueprint, request, jsonify
import pickle
import pandas as pd
from datetime import datetime, timedelta
import random

from config import Config
from app.utils.feature_extraction import extract_all_features
from app.utils.explainability import compute_tree_shap
from app.utils.policy_engine import evaluate_policy
from app.utils.honeypot_ioc import record_honeypot_quarantine, get_all_sessions, get_all_iocs
from app.utils.drift_engine import record_flow_features, compute_drift_status
from app.utils.benchmark_data import get_benchmark_report

# Create blueprint
prediction_bp = Blueprint('prediction', __name__)

# Load the trained model
try:
    with open(Config.MODEL_PATH, 'rb') as f:
        model = pickle.load(f)
    model_loaded = True
    print(f"Model successfully loaded from {Config.MODEL_PATH}")
except Exception as e:
    print(f"Error loading model: {e}")
    model = None
    model_loaded = False

EXPECTED_COLS = [
    'Fwd IAT Std', 'Bwd IAT Std', 'Flow IAT Std', 'Fwd IAT Max',
    'Flow IAT Mean', 'Flow IAT Max', 'Fwd IAT Mean', 'Fwd IAT Total',
    'Flow Duration', 'Bwd IAT Max', 'Idle Max', 'Idle Mean'
]

@prediction_bp.route('/predict', methods=['POST'])
def predict():
    """
    Core prediction endpoint with 3-tier Risk Scoring & SHAP Explainability.
    """
    try:
        if not model_loaded:
            return jsonify({'error': 'Model not loaded. Check server logs.'}), 503
            
        packet_data = request.json
        if not packet_data or len(packet_data) == 0:
            return jsonify({'error': 'Empty packet data'}), 400

        required_fields = ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port']
        for packet in packet_data:
            missing_fields = [field for field in required_fields if field not in packet]
            if missing_fields:
                return jsonify({
                    'error': f'Missing required fields in packet: {", ".join(missing_fields)}'
                }), 400

        # 1. Feature Extraction (12 Temporal Features)
        features = extract_all_features(packet_data)
        feature_df = pd.DataFrame([features])[EXPECTED_COLS]

        # 2. LightGBM Probability Inference
        probabilities = model.predict_proba(feature_df)[0].tolist()
        attack_probability = probabilities[1]

        # 3. TreeSHAP Explainability Calculation
        shap_data = compute_tree_shap(model, feature_df)

        # 4. 3-Tier Risk Score & Policy Engine Evaluation
        policy_data = evaluate_policy(attack_probability, features, packet_data)

        # 5. Record features for Model Drift Monitor
        record_flow_features(features)

        # 6. Honeypot Quarantine Routing if High Risk
        src_ip = packet_data[0].get('src_ip', '192.168.1.100')
        dst_ip = packet_data[0].get('dst_ip', '10.0.0.1')
        port = packet_data[0].get('dst_port', 80)
        
        flow_summary = {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'port': port,
            'packet_count': len(packet_data),
            'risk_score': policy_data['risk_score'],
            'attack_category': policy_data['attack_category'],
            'mitre_ttp': policy_data['mitre_ttp']
        }

        honeypot_session = None
        if policy_data['policy'] == 'QUARANTINE':
            honeypot_session = record_honeypot_quarantine(flow_summary)

        result = {
            'prediction': int(policy_data['risk_score'] >= 50.0),
            'is_attack': bool(policy_data['risk_score'] >= 50.0),
            'risk_score': policy_data['risk_score'],
            'risk_level': policy_data['risk_level'],
            'policy': policy_data['policy'],
            'policy_action': policy_data['policy_action'],
            'status_color': policy_data['status_color'],
            'policy_description': policy_data['description'],
            'attack_category': policy_data['attack_category'],
            'mitre_ttp': policy_data['mitre_ttp'],
            'confidence': round(probabilities[1] if attack_probability >= 0.5 else probabilities[0], 4),
            'attack_probability': round(attack_probability, 4),
            'probabilities': probabilities,
            'features': features,
            'shap_explanation': shap_data,
            'honeypot_session': honeypot_session.get('session_id') if honeypot_session else None
        }

        return jsonify(result)

    except ValueError as e:
        return jsonify({'error': f'Invalid data format: {str(e)}'}), 400
    except Exception as e:
        print(f"Prediction error: {str(e)}")
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@prediction_bp.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'service': 'AegisNIDS Layer 1 ML & Policy Engine',
        'model_loaded': model_loaded,
        'model_path': Config.MODEL_PATH,
        'model_version': 'Aegis-LGBM-v1.4',
        'policy_tiers': {
            'LOW': '0-29 (ALLOW)',
            'MEDIUM': '30-69 (MONITOR)',
            'HIGH': '70-100 (QUARANTINE)'
        }
    })

@prediction_bp.route('/', methods=['GET'])
def root_info():
    """Root overview endpoint."""
    return jsonify({
        'name': 'AegisNIDS API',
        'status': 'online',
        'model_loaded': model_loaded,
        'endpoints': {
            'health': '/health',
            'predict': 'POST /predict',
            'simulate': 'POST /api/simulate',
            'honeypot_sessions': 'GET /api/honeypot/sessions',
            'iocs': 'GET /api/iocs',
            'model_drift': 'GET /api/model/drift',
            'benchmarks': 'GET /api/model/benchmarks'
        }
    })

@prediction_bp.route('/api/simulate', methods=['POST'])
def simulate_traffic():
    """
    Generate synthetic packet flows for testing and live demonstration.
    Supports: 'benign', 'ddos', 'port_scan', 'brute_force', 'slowloris', 'adversarial_jitter'
    """
    try:
        data = request.get_json(silent=True) or {}
        scenario = data.get('scenario', 'benign')
        count = int(data.get('count', 14))
        count = max(4, min(count, 50))
        
        now = datetime.utcnow()
        packets = []
        attacker_ip = "192.168.1.105" if scenario == "benign" else "203.0.113.42"
        target_ip = "10.0.0.1"
        src_port = random.randint(49152, 65535)
        current_time = now - timedelta(seconds=2)
        
        if scenario == 'ddos':
            for i in range(count):
                current_time += timedelta(microseconds=random.randint(150, 950))
                packets.append({
                    "timestamp": current_time.isoformat(),
                    "src_ip": attacker_ip,
                    "dst_ip": target_ip,
                    "src_port": src_port,
                    "dst_port": 80
                })
        elif scenario == 'port_scan':
            target_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080]
            for i in range(count):
                current_time += timedelta(microseconds=random.randint(800, 3500))
                packets.append({
                    "timestamp": current_time.isoformat(),
                    "src_ip": attacker_ip,
                    "dst_ip": target_ip,
                    "src_port": src_port,
                    "dst_port": target_ports[i % len(target_ports)]
                })
        elif scenario == 'slowloris':
            for i in range(count):
                idle_us = random.randint(600000, 1500000) if i % 2 == 1 else random.randint(5000, 20000)
                current_time += timedelta(microseconds=idle_us)
                packets.append({
                    "timestamp": current_time.isoformat(),
                    "src_ip": attacker_ip,
                    "dst_ip": target_ip,
                    "src_port": src_port,
                    "dst_port": 80
                })
        elif scenario == 'brute_force':
            for i in range(count):
                current_time += timedelta(microseconds=random.randint(2000, 12000))
                packets.append({
                    "timestamp": current_time.isoformat(),
                    "src_ip": attacker_ip,
                    "dst_ip": target_ip,
                    "src_port": src_port if i % 2 == 0 else random.randint(49152, 65535),
                    "dst_port": 22
                })
        elif scenario == 'adversarial_jitter':
            # Attacker attempting to evade temporal detection with random delays
            for i in range(count):
                current_time += timedelta(microseconds=random.randint(45000, 220000))
                packets.append({
                    "timestamp": current_time.isoformat(),
                    "src_ip": attacker_ip,
                    "dst_ip": target_ip,
                    "src_port": src_port,
                    "dst_port": 80
                })
        else:  # benign
            dst_port = 443
            for i in range(count):
                is_fwd = (i % 2 == 0)
                delta_us = random.randint(25000, 120000)
                current_time += timedelta(microseconds=delta_us)
                packets.append({
                    "timestamp": current_time.isoformat(),
                    "src_ip": attacker_ip if is_fwd else target_ip,
                    "dst_ip": target_ip if is_fwd else attacker_ip,
                    "src_port": src_port if is_fwd else dst_port,
                    "dst_port": dst_port if is_fwd else src_port
                })

        # Run inference
        features = extract_all_features(packets)
        feature_df = pd.DataFrame([features])[EXPECTED_COLS]
        probabilities = model.predict_proba(feature_df)[0].tolist() if model_loaded else [0.5, 0.5]
        attack_probability = probabilities[1]
        
        shap_data = compute_tree_shap(model, feature_df) if model_loaded else {'top_drivers': [], 'explanation': 'Model not loaded'}
        policy_data = evaluate_policy(attack_probability, features, packets)
        record_flow_features(features)

        honeypot_session = None
        if policy_data['policy'] == 'QUARANTINE':
            honeypot_session = record_honeypot_quarantine({
                'src_ip': attacker_ip,
                'dst_ip': target_ip,
                'port': packets[0]['dst_port'],
                'packet_count': len(packets),
                'risk_score': policy_data['risk_score'],
                'attack_category': policy_data['attack_category'],
                'mitre_ttp': policy_data['mitre_ttp']
            })

        return jsonify({
            'scenario': scenario,
            'packet_count': len(packets),
            'packets': packets,
            'prediction': int(policy_data['risk_score'] >= 50.0),
            'is_attack': bool(policy_data['risk_score'] >= 50.0),
            'risk_score': policy_data['risk_score'],
            'risk_level': policy_data['risk_level'],
            'policy': policy_data['policy'],
            'policy_action': policy_data['policy_action'],
            'status_color': policy_data['status_color'],
            'policy_description': policy_data['description'],
            'attack_category': policy_data['attack_category'],
            'mitre_ttp': policy_data['mitre_ttp'],
            'confidence': round(probabilities[1] if attack_probability >= 0.5 else probabilities[0], 4),
            'attack_probability': round(attack_probability, 4),
            'features': features,
            'shap_explanation': shap_data,
            'honeypot_session': honeypot_session.get('session_id') if honeypot_session else None
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@prediction_bp.route('/api/honeypot/sessions', methods=['GET'])
def get_honeypot_sessions():
    """Retrieve all active and recorded honeypot sessions and captured commands."""
    sessions = get_all_sessions()
    return jsonify({
        'sessions_count': len(sessions),
        'sessions': sessions
    })

@prediction_bp.route('/api/iocs', methods=['GET'])
def get_iocs():
    """Retrieve extracted Indicators of Compromise (IOCs)."""
    iocs = get_all_iocs()
    return jsonify({
        'iocs_count': len(iocs),
        'iocs': iocs
    })

@prediction_bp.route('/api/model/drift', methods=['GET'])
def get_model_drift():
    """Check feature distribution drift against training baseline."""
    drift_data = compute_drift_status()
    return jsonify(drift_data)

@prediction_bp.route('/api/model/benchmarks', methods=['GET'])
def get_benchmarks():
    """Retrieve research benchmark comparisons across datasets and models."""
    report = get_benchmark_report()
    return jsonify(report)

@prediction_bp.route('/api/pcap/upload', methods=['POST'])
def upload_pcap():
    """
    Ingest, reconstruct, and analyze a PCAP capture file.
    Supports multipart/form-data upload or JSON path reference.
    """
    import os
    from app.utils.pcap_processor import process_pcap_file
    
    threshold = float(request.form.get('threshold', 0.035))
    target_pcap_path = None
    
    if 'file' in request.files:
        pcap_file = request.files['file']
        if pcap_file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
            
        uploads_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'uploads')
        os.makedirs(uploads_dir, exist_ok=True)
        target_pcap_path = os.path.join(uploads_dir, pcap_file.filename)
        pcap_file.save(target_pcap_path)
    else:
        data = request.get_json(silent=True) or {}
        target_pcap_path = data.get('pcap_path')
        if not target_pcap_path or not os.path.exists(target_pcap_path):
            return jsonify({'error': 'Valid file or pcap_path parameter required'}), 400
            
    try:
        results = process_pcap_file(
            pcap_path=target_pcap_path,
            model=model,
            threshold=threshold,
            quarantine_high_risk=True
        )
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': f'PCAP processing error: {str(e)}'}), 500

@prediction_bp.route('/api/analysis/attack-types', methods=['GET'])
def get_attack_types_analysis():
    """Per-category attack detection breakdown."""
    from app.utils.attack_evaluator import run_attack_type_evaluation
    threshold = float(request.args.get('threshold', 0.035))
    results = run_attack_type_evaluation(model=model, threshold=threshold)
    return jsonify(results)

@prediction_bp.route('/api/analysis/thresholds', methods=['GET'])
def get_thresholds_analysis():
    """Threshold sensitivity curve across boundaries 0.01 to 0.90."""
    from app.utils.threshold_analyzer import run_threshold_sensitivity_analysis
    results = run_threshold_sensitivity_analysis(model=model)
    return jsonify(results)

@prediction_bp.route('/api/analysis/jitter', methods=['GET'])
def get_jitter_analysis():
    """Adversarial timing jitter evasion experiment results."""
    from app.utils.jitter_experiment import run_adversarial_jitter_experiment
    results = run_adversarial_jitter_experiment(model=model)
    return jsonify(results)

@prediction_bp.route('/api/analysis/throughput', methods=['GET'])
def get_throughput_analysis():
    """High-throughput concurrency stress test results."""
    from app.utils.throughput_benchmark import run_throughput_stress_benchmark
    results = run_throughput_stress_benchmark(model=model)
    return jsonify(results)

@prediction_bp.route('/api/analysis/models', methods=['GET'])
def get_models_analysis():
    """Empirical architectural model comparison (Model A vs B vs C)."""
    from app.utils.model_comparison import run_model_architecture_comparison
    results = run_model_architecture_comparison()
    return jsonify(results)