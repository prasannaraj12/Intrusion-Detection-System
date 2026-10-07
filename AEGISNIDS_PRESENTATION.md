# AegisNIDS: Autonomous Two-Layer Network Intrusion Detection & Forensic Quarantine System
## Final Technical & Research Defense Presentation (10 Slides)

---

### Slide 1: Problem & Motivation — The Encryption & Line-Rate Crisis
**The Fundamental Dilemma of Modern Enterprise Security:**
- **Payload Opacity:** Over 85% of modern enterprise and web traffic is encrypted end-to-end (TLS 1.3, QUIC, DoH). Traditional Deep Packet Inspection (DPI) that inspects L7 payloads fails without expensive, intrusive SSL/TLS decryption proxies that violate privacy and break forward secrecy.
- **Line-Rate Latency Bottlenecks:** Heavy 84-feature extractors (e.g. CICFlowMeter) incur packet buffering and reassembly delays (>25 ms), causing queue backpressure and packet drops on multi-gigabit pipes.
- **Alert Fatigue & Black-Box Inaction:** Conventional ML-based NIDS output brittle binary labels ("Attack" vs "Benign") without explanation, overwhelming SOC analysts and providing no automated containment.

---

### Slide 2: Proposed Solution — AegisNIDS
**An Autonomous, Explainable, Two-Layer Defense Ecosystem:**
> **"AegisNIDS detects network attacks using lightweight ML, determines response severity through a policy engine, contains high-risk traffic in a honeypot, extracts forensic IOCs, and exports standardized STIX 2.1 threat intelligence."**

**Core Pillars:**
1. **Zero-DPI Temporal Detection:** Classifies traffic using only 12 inter-arrival time and flow duration metrics—100% payload-independent.
2. **Sub-Millisecond TreeSHAP:** Provides local feature attribution in <0.5 ms so analysts immediately know *why* a flow was flagged.
3. **Calibrated 3-Tier Policy:** Replaces rigid cutoffs with graduated actions: `ALLOW`, `MONITOR`, and `QUARANTINE`.
4. **Forensic Honeypot Quarantine:** Traps high-risk adversaries in Layer 2 decoys, extracting IOCs and feeding closed-loop MLOps.

---

### Slide 3: System Architecture — End-to-End Pipeline
```text
[ Raw Network Packets / PCAP ]
              │
              ▼
[ 5-Tuple Flow Reconstruction Engine ] ──── (Canonical keys, 5s timeout, microsecond tracking)
              │
              ▼
[ 12 Zero-DPI Temporal Feature Extractor ] ─ (Flow Duration, Fwd/Bwd/Flow IAT, Idle Variance)
              │
              ▼
[ Layer 1: Aegis-LGBM Engine ] ──────────── (Calibrated gradient boosted decision trees)
              │
       ┌──────┴────────────────────────┐
       ▼                               ▼
[ Native TreeSHAP Attribution ]   [ 3-Tier Policy Engine ]
(Exact local root-cause text)     (Calibrated risk score: 0 - 100)
                                       │
                 ┌─────────────────────┼─────────────────────┐
                 ▼                     ▼                     ▼
          [ ALLOW: < 20 ]       [ MONITOR: 20-74 ]    [ QUARANTINE: >= 75 ]
          Normal Egress         SOC Watchlist Alert   Divert to Layer 2 Honeypot
                                                             │
                                                             ▼
                                                    [ Forensic Honeypot Decoy ]
                                                    (Interactive shell / sinkhole)
                                                             │
                                                             ▼
                                                    [ Automated IOC Engine ]
                                                    (IPs, payload hashes, ports)
                                                             │
                                                             ▼
                                                    [ STIX 2.1 Threat Intel ]
                                                    (OASIS validated bundles)
```

---

### Slide 4: Machine Learning Detection Layer
**Mathematical Modeling of Packet Cadence:**
- **The 12 Temporal Features:**
  - Forward Direction: `Fwd IAT Mean`, `Fwd IAT Std`, `Fwd IAT Max`, `Fwd IAT Total`
  - Global Dynamics: `Flow Duration`, `Flow IAT Mean`, `Flow IAT Std`, `Flow IAT Max`
  - Backward Direction: `Bwd IAT Max`, `Bwd IAT Std`
  - Session Inactivity: `Idle Mean`, `Idle Max`
- **Inference Efficiency:** LightGBM decision forest serialized at only 352 KB.
- **Latency Benchmark (Audited 720 warm cycles):**
  - Feature Extraction: **0.20 ms** median (p95: 0.31 ms)
  - Model Inference: **1.21 ms** median (p95: 2.01 ms)
  - Total Detection Pipeline: **1.98 ms** median (p95: 3.16 ms)
  - Vector Throughput: **>800,000 flows/sec** in batch mode.

---

### Slide 5: Three-Tier Response Policy + Honeypot Decoy
**From Binary Guesswork to Graduated Operational Containment:**
- **Tier 1 — ALLOW ($P < 0.20$):**
  - Legitimate business traffic egresses to internal networks unimpeded.
  - Achieves **96.4% benign purity** on real enterprise traffic.
- **Tier 2 — MONITOR ($0.20 \le P < 0.75$):**
  - Anomalous bursts placed on passive SOC telemetry watchlist.
  - Generates real-time MITRE ATT&CK technique mapping without interrupting service.
- **Tier 3 — QUARANTINE ($P \ge 0.75$):**
  - High-confidence threats automatically rerouted to Layer 2 Honeypot decoy.
  - Achieves **98.87% quarantine precision** with only **0.66% false quarantine rate**.
  - Traps attackers in interactive SSH/HTTP decoys, logging full command history.

---

### Slide 6: Automated IOC Extraction & STIX 2.1 Threat Sharing
**Actionable Threat Intelligence at Machine Speed:**
- **Autonomous Forensic Harvesting:**
  - Extracts malicious IPs, target ports, protocol vectors, and payload hashes from quarantined sessions.
  - Assigns calibrated threat severity and confidence scores (e.g. `IOC-001`: 98% confidence).
- **OASIS STIX 2.1 Standardized Export:**
  - Implements RFC 4122 v4 UUIDs, ISO-8601 UTC timestamps, and valid STIX pattern grammar (`[ipv4-addr:value = '...']`).
  - **100% Validated:** Verified with zero schema errors by the official OASIS `python-stix2` library.
  - Ready for native ingestion into enterprise SIEM platforms (Splunk, Elastic) and threat exchanges (MISP, OpenCTI).

---

### Slide 7: SOC Monitoring Center & Native TreeSHAP
**Live Operational Visibility:**
- **Web Dashboard:** Real-time SOC interface displaying live analyzed flows, active policy breakdown, and sandbox telemetry.
- **Native Sub-Millisecond TreeSHAP:**
  - Calculates exact Shapley feature attributions directly from tree structures (`pred_contrib=True`) in $<0.5\text{ ms}$.
  - Replaces model-agnostic perturbations (which require 500+ passes) with deterministic C++ attribution.
- **Human-Readable Analyst Guidance:**
  > *"Flagged primarily due to abnormal Fwd IAT Total (+1.2325) and elevated Fwd IAT Mean (+1.2278) [Direct SYN Flood Cadence]"*

---

### Slide 8: Real CIC-IDS2017 Empirical Validation
**Real-World Network Data (20,000 Stratified Flows from Friday & Tuesday):**

| Empirical Metric | Measured Value | Operational Meaning |
| :--- | :---: | :--- |
| **ROC-AUC** | **97.17%** | Near-optimal discriminative separation across full range |
| **Recall (Sensitivity)** | **97.41%** | 9,741 / 10,000 attacks intercepted at the perimeter |
| **False Negative Rate** | **2.59%** | Only 2.59% of real attacks evade the perimeter trigger |
| **DDoS Detection Rate** | **99.97%** | 3,499 / 3,500 LOIC flood flows caught |
| **PortScan Detection Rate** | **99.89%** | 3,496 / 3,500 recon scan flows caught |
| **SSH-Patator Detection Rate** | **99.67%** | 1,495 / 1,500 brute-force flows caught |
| **FTP-Patator Detection Rate** | **83.40%** | Identified temporal limitation; resolved by Model B |
| **F1-Score (All Vectors)** | **87.51%** | Balanced harmonic precision/recall on real data |

---

### Slide 9: Model Comparison & Scientific Limitations
**Model A (12 Features) vs. Model B (24 Features) on Tuesday Patator:**

| Dimension | Model A (Zero-DPI Pure) | Model B (Extended Flow) | Empirical Gain / Finding |
| :--- | :---: | :---: | :---: |
| **Features** | 12 (Temporal Only) | 24 (Temporal + Port + Flags) | +12 transport-layer features |
| **F1-Score** | 88.37% | **99.86%** | **+11.49% F1 improvement** |
| **Precision** | 79.28% | **99.71%** | Eliminates LAN false alarms |
| **FPR** | 18.05% | **0.20%** | Drops false alarm rate by 90x |
| **FTP Brute-Force Recall** | 82.41% | **99.98%** | **Completely resolves blind spot** |
| **Inference Latency** | 1.154 ms | 1.171 ms | Minimal 17 μs latency delta |

**Documented Research Limitations:**
1. *Cross-Attack Generalization:* Models trained solely on volumetric floods achieve 21.4% zero-shot recall on brute force due to divergent timing physics. Multi-vector training is essential.
2. *CSE-CIC-IDS2018 Status:* Present as local Parquet artifact, but explicitly marked **`AVAILABLE, NOT VALIDATED`** due to missing ground-truth labels to prevent fabricated claims.

---

### Slide 10: Conclusion & Operational Impact
**Defensible, Reproducible, Production-Oriented Network Defense:**

- **Complete Verified Chain:**
  $$\text{Real Packets} \rightarrow \text{Zero-DPI Flows} \rightarrow \text{LightGBM} \rightarrow \text{TreeSHAP} \rightarrow \text{3-Tier Policy} \rightarrow \text{Honeypot} \rightarrow \text{STIX 2.1}$$
- **Key Empirical Takeaways:**
  - **1.98 ms** detection pipeline enables true line-rate real-time evaluation.
  - **97.17% ROC-AUC** on real CIC-IDS2017 proves pure temporal features carry strong discriminative power even without payload inspection.
  - Model B resolves the authentication brute-force blind spot with 99.86% F1 and 0.20% FPR.
  - Closed-loop honeypot captures produce OASIS-compliant STIX 2.1 intelligence ready for SOC ingestion.
- **Future Directions:** eBPF kernel offload for 10 Gbps+ line rate and self-supervised flow representation learning.
