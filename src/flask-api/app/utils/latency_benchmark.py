"""
Canonical Latency Benchmark Engine for AegisNIDS.
Provides ONE authoritative, standardized, and reproducible latency measurement:
- Model already loaded (no reload penalty)
- 30-flow warm-up procedure
- Fixed random seed (1337)
- Standard 240 evaluation flows
- 3 repetitions (720 measurements per stage)
- Separate stage timing:
    A. Feature extraction
    B. DataFrame preparation
    C. Model inference
    D. Total detection pipeline
- High-precision time.perf_counter()
- Garbage collection controlled during timed repetitions
- Persistent disk cache to guarantee identical canonical numbers across API and test suite
"""
import os
import json
import time
import gc
import pickle
import numpy as np
import pandas as pd

from config import Config
from app.utils.feature_extraction import extract_all_features

EXPECTED_12_COLS = [
    'Fwd IAT Std', 'Bwd IAT Std', 'Flow IAT Std', 'Fwd IAT Max',
    'Flow IAT Mean', 'Flow IAT Max', 'Fwd IAT Mean', 'Fwd IAT Total',
    'Flow Duration', 'Bwd IAT Max', 'Idle Max', 'Idle Mean'
]

METHODOLOGY_ID = "warm_canonical_benchmark_3x240_flows"
METHODOLOGY_DESC = (
    "Standardized warm-start benchmark over 240 evaluation flows with 3 repetitions "
    "(720 total measurements per stage), measuring feature extraction, DataFrame preparation, "
    "model inference, and total ML pipeline using time.perf_counter() under GC control."
)

_CACHE_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'canonical_latency.json')
_IN_MEMORY_CACHE = None

def run_canonical_latency_benchmark(model=None, dataset=None, warmup_flows=30, repetitions=3):
    """
    Execute the standardized canonical latency benchmark.
    Returns:
        dict: Complete latency breakdown across all 4 stages with summary statistics.
    """
    global _IN_MEMORY_CACHE
    
    # 1. Ensure model is loaded
    if model is None:
        with open(Config.MODEL_PATH, 'rb') as f:
            model = pickle.load(f)
            
    # 2. Ensure dataset is generated with fixed seed
    if dataset is None:
        from app.utils.empirical_evaluator import generate_benchmark_dataset
        dataset = generate_benchmark_dataset(num_benign=120, num_attacks=120, seed=1337)

    # 3. Warm-up phase (30 flows through complete pipeline)
    for item in dataset[:warmup_flows]:
        _wf = extract_all_features(item['packets'])
        _wdf = pd.DataFrame([_wf])[EXPECTED_12_COLS]
        _ = model.predict_proba(_wdf)[0]
        
    feat_times = []
    df_times = []
    inf_times = []
    total_times = []
    
    # 4. Controlled timing phase
    gc.collect()
    gc.disable()
    try:
        for rep in range(repetitions):
            for item in dataset:
                pkts = item['packets']
                
                # Stage A: Feature Extraction
                t0 = time.perf_counter()
                feats = extract_all_features(pkts)
                t1 = time.perf_counter()
                
                # Stage B: DataFrame Preparation
                df = pd.DataFrame([feats])[EXPECTED_12_COLS]
                t2 = time.perf_counter()
                
                # Stage C: Model Inference
                _ = model.predict_proba(df)[0]
                t3 = time.perf_counter()
                
                feat_times.append((t1 - t0) * 1000.0)
                df_times.append((t2 - t1) * 1000.0)
                inf_times.append((t3 - t2) * 1000.0)
                total_times.append((t3 - t0) * 1000.0)
    finally:
        gc.enable()
        
    def summarize(arr):
        return {
            'median': round(float(np.median(arr)), 2),
            'p95': round(float(np.percentile(arr, 95)), 2),
            'min': round(float(np.min(arr)), 2),
            'max': round(float(np.max(arr)), 2),
            'mean': round(float(np.mean(arr)), 2)
        }
        
    result = {
        'methodology': METHODOLOGY_ID,
        'methodology_description': METHODOLOGY_DESC,
        'evaluated_flows': len(dataset),
        'repetitions': repetitions,
        'warmup_flows': warmup_flows,
        'total_measurements_per_stage': len(feat_times),
        'timestamp': time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        'feature_extraction_ms': summarize(feat_times),
        'dataframe_preparation_ms': summarize(df_times),
        'model_inference_ms': summarize(inf_times),
        'total_detection_ms': summarize(total_times)
    }
    
    # Save to persistent file
    try:
        os.makedirs(os.path.dirname(_CACHE_FILE), exist_ok=True)
        with open(_CACHE_FILE, 'w') as f:
            json.dump(result, f, indent=2)
    except Exception as e:
        print(f"Warning: Could not save canonical latency cache: {e}")
        
    _IN_MEMORY_CACHE = result
    return result

def get_canonical_latency(force_refresh=False):
    """
    Retrieve the single authoritative canonical latency result.
    If cached on disk or in memory, returns it directly to ensure perfect consistency.
    """
    global _IN_MEMORY_CACHE
    
    if _IN_MEMORY_CACHE is not None and not force_refresh:
        return _IN_MEMORY_CACHE
        
    if not force_refresh and os.path.exists(_CACHE_FILE):
        try:
            with open(_CACHE_FILE, 'r') as f:
                data = json.load(f)
                if data.get('methodology') == METHODOLOGY_ID:
                    _IN_MEMORY_CACHE = data
                    return data
        except Exception:
            pass
            
    return run_canonical_latency_benchmark()
