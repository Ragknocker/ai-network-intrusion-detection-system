# Detailed Project Report: Intelligent Network Intrusion Detection System (AI-NIDS)

## 1. Executive Summary

The **Intelligent Network Intrusion Detection System (AI-NIDS)** is a comprehensive cybersecurity solution designed to protect modern network infrastructures from sophisticated cyber threats. Unlike traditional rule-based firewalls and NIDS that struggle with novel zero-day attacks and polymorphic malware, AI-NIDS leverages a hybrid machine learning architecture. It actively combines supervised learning models for known threat classification with heuristic and statistical anomaly detection for zero-day identification. The system is paired with a real-time Security Operations Center (SOC) dashboard, enabling analysts to visualize telemetry, review AI classifications, and implement mitigation strategies interactively.

## 2. System Architecture

The AI-NIDS framework is built on a modern, decoupled architecture allowing for scalable deployment in both containerized (Docker) and serverless (AWS Lambda) environments.

### 2.1. Frontend: Interactive SOC Dashboard
The SOC Dashboard serves as the primary interface for security operations personnel.
- **Technology Stack:** React 19, Vite, and Tailwind CSS.
- **Visualizations:** Recharts is utilized for dynamic telemetry rendering (e.g., bandwidth spikes, threat origins).
- **Functionality:** Provides real-time metrics on network traffic, URL threats, and file quarantine statuses.

### 2.2. Backend Services & API
The backend handles telemetry ingestion, orchestrates threat scanning, and serves the dashboard via RESTful endpoints.
- **API Framework:** FastAPI (simulated in `api.py`) for high-throughput, asynchronous request processing.
- **Serverless Integration:** AWS Lambda compatibility (`lambda_handler.py`) enables the system to operate as a scalable API Gateway backend, handling network flows, file uploads, and URL validations seamlessly.
- **Data Persistence:** PostgreSQL integration via `psycopg2` and SQLAlchemy for logging threat alerts and audit trails.

### 2.3. Hybrid Machine Learning Detection Engine
The core of AI-NIDS relies on a combination of machine learning and heuristic engines designed for high accuracy and low false-positive rates.
- **Core ML Library:** `scikit-learn` with `pandas` and `numpy`.
- **Supervised Model:** A **Random Forest Classifier** (`n_estimators=100`, `max_depth=15`) is trained to identify and categorize multi-class attacks (e.g., DDoS, Port Scans, SQL Injections, Malware C2).
- **Heuristic Engine:** Utilizes Shannon Entropy calculations and regex pattern matching to identify obfuscated payloads, Domain Generation Algorithms (DGA), and zero-day deviations.

## 3. Implementation Details & Modules

The system is compartmentalized into several specific threat analysis modules.

### 3.1. Network Traffic Analysis
The system ingests network flows and extracts key features:
- **Extracted Features:** `src_port`, `dest_port`, `size`, `entropy`, `flags_syn`, and protocol type (TCP, UDP, ICMP - which are one-hot encoded).
- **Prediction Pipeline:** Traffic vectors are fed into the pre-trained Random Forest model (`rf_nids_model.pkl`). The model outputs a classification (e.g., 'Normal', 'DDoS', 'Port Scan') and a confidence-based `threatScore`.

### 3.2. URL & Domain Intelligence Inspector
An advanced URL inspection module evaluates external links and domains for phishing and malware risks.
- **Heuristics & Threat Scoring:** Evaluates URLs against criteria such as missing SSL encryption, raw IP usage, high-risk TLDs (e.g., `.xyz`, `.top`), and typosquatting (e.g., `paypa1`, `g00gle`).
- **Domain Entropy (DGA Detection):** Calculates Shannon Entropy on hostnames. A high entropy score (e.g., > 3.8) flags the domain as a potential Domain Generation Algorithm (DGA) commonly used by botnets.
- **Pre-filtering:** Implements a two-stage filter checking against known Allow-lists (safe corporate domains) and Block-lists (known threat feeds) before routing to the AI classifier.
- **Analyst Feedback Loop:** Supports endpoints (`/url/feedback`, `/url/retrain`) for analysts to correct false positives/negatives, which actively triggers model retraining and monitors for concept drift.

### 3.3. File & Payload Threat Scanner
Inspects uploaded files and network-captured payloads for malicious signatures and arbitrary code execution.
- **Code Payload Analysis:** Scans for Remote Code Execution (RCE) patterns (e.g., `eval`, `shell_exec`), Obfuscated WebShells (e.g., `base64_decode`), SQL Injection patterns, and DOM XSS (`innerHTML`).
- **File Header & Entropy Analysis:** Files with unusually high entropy (e.g., > 5.3) are flagged as potential encrypted droppers or packed executables. 
- **Log Analysis:** Specifically scans `.csv`, `.pcap`, and `.log` files for DDoS signatures (SYN Floods, HTTP GET Floods) and Reconnaissance activities (Nmap).

## 4. Dataset Generation & Training
For development and simulation, AI-NIDS incorporates a synthetic dataset generation module (`generate_dataset.py`).
- **Generation:** Synthesizes realistic network flow records incorporating normal traffic and simulated attack vectors (DDoS, Port Scan, SQL Injection, Malware C2, Zero-Day).
- **Feature Variance:** Malicious flows are injected with specific characteristics (e.g., Port Scans feature small packet sizes and high entropy; DDoS features high packet sizes and SYN flags).
- **Training Pipeline:** The `train_model.py` script loads this dataset, splits it (80/20 train/test), and trains the Random Forest classifier, subsequently evaluating its accuracy, precision, and recall via confusion matrices.

## 5. Containerization and Deployment
AI-NIDS is designed for seamless deployment across varied environments.
- **Docker Compose:** Utilizes `docker-compose.yml` and `Dockerfile` to deploy the application, ensuring consistency across development and production environments.
- **Nginx Reverse Proxy:** Incorporates an `nginx.conf` file to act as a reverse proxy, handling static assets and routing API requests to the backend securely.
- **Serverless Docker:** Includes `Dockerfile.lambda` tailored for deploying the analysis engine directly to AWS Lambda for highly scalable, event-driven threat analysis.

## 6. Conclusion & Future Enhancements

The Intelligent Network Intrusion Detection System successfully demonstrates a proactive, hybrid approach to network security. By synthesizing machine learning with targeted heuristic analysis, AI-NIDS can accurately detect both known attacks and obfuscated zero-day threats in real-time.

**Future Scope:**
- **Deep Learning Integration:** Implementing Long Short-Term Memory (LSTM) networks or Autoencoders for more robust sequential anomaly detection over time-series network data.
- **Distributed Agent Architecture:** Deploying lightweight AI-NIDS sensors across enterprise subnets to report telemetry back to a centralized SIEM database.
- **Automated Active-Response:** Expanding the SOAR (Security Orchestration, Automation, and Response) capabilities to automatically generate firewall rules and network isolation commands in response to critical threats.
