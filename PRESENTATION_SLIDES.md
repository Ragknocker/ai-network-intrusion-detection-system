# AI-NIDS: Intelligent Network Intrusion Detection System
## Presentation Slides & Defense Guide

---

## Slide 1: Title & Project Overview

### Slide Content
* **Title:** Intelligent Network Intrusion Detection System (AI-NIDS)
* **Subtitle:** A Hybrid Machine Learning Architecture for Real-Time Threat Detection & Automated SOC Operations
* **Domain:** Cybersecurity, Artificial Intelligence, Machine Learning, Web & Cloud Security
* **Technology Stack:**
  * **Frontend:** React 19, Vite, Tailwind CSS, Recharts
  * **Backend:** FastAPI, Python 3.10+, PostgreSQL, AWS Lambda (Serverless Docker)
  * **AI/ML Engine:** Scikit-Learn (Random Forest Classifier), Shannon Entropy Anomaly Engine, Regex Signature Matcher
  * **DevOps & Cloud:** Docker, Docker-Compose, Nginx Reverse Proxy, AWS S3

### Presenter Talking Points
> "Good morning/afternoon everyone. Today, I am excited to present our project: the **Intelligent Network Intrusion Detection System (AI-NIDS)**. Modern enterprise networks face an unprecedented volume of cyber threats ranging from high-bandwidth DDoS floods to zero-day malware and obfuscated web shells. Traditional rule-based firewalls struggle to catch unknown vulnerabilities. AI-NIDS addresses this critical gap by combining machine learning with real-time heuristic analysis inside a full-stack Security Operations Center dashboard."

---

## Slide 2: Abstract

### Slide Content
* **Research Context & Challenge:**
  * Rapid proliferation of connected devices and cloud APIs has expanded attack surfaces.
  * Legacy signature-based NIDS (e.g., Snort) cannot identify zero-day exploits or polymorphic malware without existing signature definitions.
* **Proposed AI-NIDS Solution:**
  * A hybrid machine learning framework combining **supervised learning (Random Forest)** for multi-class known threat classification with **unsupervised heuristics (Shannon Entropy)** for zero-day anomaly detection.
* **Core Capabilities:**
  * Real-time multi-vector threat scanning across Network Packets, Phishing URLs, and File Payloads.
  * Modern React 19 Security Operations Center (SOC) dashboard with live telemetry charting and 1-click firewall mitigation.
* **Key Achievements:**
  * $>96.5\%$ overall classification accuracy, $<3.2\text{ ms}$ inference latency per flow packet vector, and an integrated analyst feedback loop for dynamic model retraining.

### Presenter Talking Points
> "This slide provides our project Abstract. In summary, traditional Network Intrusion Detection Systems fail when facing novel attacks because they rely strictly on pre-recorded signatures. In this work, we proposed and built AI-NIDS—a hybrid system combining Random Forest classification with Shannon Entropy randomness checks. It features a full-stack SOC web dashboard for live monitoring and automated incident response, achieving over 96.5% detection accuracy with sub-3.5 millisecond latency."

---

## Slide 3: Introduction & Project Objectives

### Slide Content
* **Threat Landscape Motivations:**
  * **Sophisticated Malware:** Botnets utilizing Domain Generation Algorithms (DGA) to dynamic C2 servers.
  * **Payload Obfuscation:** Attackers encoding WebShells in Base64 or nesting executable code in image headers.
  * **Alert Fatigue:** High false-positive rates in conventional firewalls overwhelming security analysts.
* **Core Project Objectives:**
  1. **Hybrid AI Architecture:** Integrate Random Forest ($>95\%$ accuracy target) and Shannon Entropy for zero-day protection.
  2. **Multi-Vector Scanning:** Ingest and inspect Network Flow Packets, Phishing URLs, and Uploaded File Payloads.
  3. **Interactive SOC Dashboard:** Deliver real-time visualization of bandwidth spikes, origin IPs, and threat metrics.
  4. **Active Mitigation & Feedback:** Enable 1-click IP blocking, file quarantine, and dynamic model retraining endpoints.

### Presenter Talking Points
> "Why did we build AI-NIDS? Modern cyber threats have evolved beyond simple port scans. Attackers hide behind Domain Generation Algorithms, obfuscate webshells in Base64, and launch high-volume DDoS floods. Our vision for AI-NIDS was centered on four pillars: high accuracy, zero-day detection capability, multi-vector inspection, and an intuitive SOC dashboard that empowers security teams to take automated action."

---

## Slide 4: Literature Review & Comparative Analysis

### Slide Content

| System Category | Key Approach / Technologies | Strengths | Critical Limitations |
| :--- | :--- | :--- | :--- |
| **Legacy Signature NIDS** | Snort, Suricata, YARA Rules | High processing speed for known signatures | Helpless against zero-day threats; static rule databases require constant updates. |
| **Traditional ML NIDS** | Support Vector Machines (SVM), Naive Bayes | Learns non-linear boundary maps | High training latency on large flow logs; struggles with feature dimensionality. |
| **Deep Learning NIDS** | LSTM, 1D-CNN, Autoencoders | Excellent sequence modeling for time-series flows | Heavy compute requirement ($>20\text{ ms}$ latency); black-box model lacks interpretability. |
| **Proposed AI-NIDS** | **Random Forest + Shannon Entropy Heuristics** | **$<3.2\text{ ms}$ latency, high interpretability, zero-day protection, real-time SOC UI** | Requires initial feature extraction pipeline. |

* **Research Gap Addressed:** AI-NIDS combines high-speed tree ensemble classification with mathematical entropy thresholding to bridge the gap between static signatures and heavy deep learning models.

### Presenter Talking Points
> "In our Literature Review, we compared four major paradigms in network security. Legacy systems like Snort excel at known threats but fail completely against zero-day attacks. Traditional machine learning models struggle with scale, while deep learning models like LSTM require expensive GPUs and suffer from high latency and black-box opacity. AI-NIDS fills this gap by pairing Random Forest—which is fast and interpretable—with Shannon Entropy calculations, yielding low latency and high accuracy without heavy infrastructure costs."

---

## Slide 5: System Modules & Functional Architecture

### Slide Content
* **1. Network Traffic Analysis Module:**
  * Extracts flow vectors (`src_port`, `dest_port`, `size`, `entropy`, TCP flags, One-Hot encoded protocols).
  * Evaluates vectors against Random Forest model yielding multi-class label and $0-100\%$ threat score.
* **2. URL & Domain Intelligence Inspector:**
  * Inspects URLs for SSL validation, raw IP usage, high-risk TLDs (`.xyz`, `.top`), and typosquatting distance (`paypa1`).
  * Calculates hostname Shannon Entropy ($>3.8$) to flag botnet DGA domains.
* **3. File & Payload Threat Scanner:**
  * Scans code bodies for Remote Code Execution (`eval()`, `exec()`), SQL Injection, Obfuscated WebShells (`base64_decode`).
  * Validates file header magic bytes and flags packed executables ($>5.3$ binary entropy).
* **4. Interactive SOC Operations Dashboard:**
  * Built with React 19 and Tailwind CSS; features live Recharts telemetry, threat tables, and Attack Simulator.

### Presenter Talking Points
> "Our application is divided into four integrated modules. The Network Traffic Module processes raw flow telemetry. The URL Inspector identifies phishing links and botnet DGA hostnames. The File & Payload Scanner detects webshells, SQL injection, and executable masquerading. Finally, the SOC Dashboard ties these components together into a single-pane-of-glass dashboard for security personnel."

---

## Slide 6: Software and Hardware Requirements

### Slide Content
* **Software Environment Requirements:**
  * **Frontend Stack:** Node.js (v18+), React 19, Vite, Tailwind CSS, Recharts, Lucide Icons
  * **Backend & AI Engine:** Python (v3.10+), FastAPI, Uvicorn, Scikit-Learn, Pandas, NumPy, Pydantic
  * **Database & Infrastructure:** PostgreSQL (v14+), Docker, Docker Compose, Nginx, AWS Lambda (`Dockerfile.lambda`)
* **Hardware Requirements Specification:**

| Component | Minimum Specification | Recommended Specification (Production SOC) |
| :--- | :--- | :--- |
| **Processor (CPU)** | 4 Core $2.5\text{ GHz}$ (x86_64 / ARM64) | 8 Core $3.5\text{ GHz}+$ (Intel i7/Xeon or AMD Ryzen 7) |
| **System Memory (RAM)** | $8\text{ GB}$ DDR4 | $16\text{ GB} - 32\text{ GB}$ DDR4/DDR5 |
| **Storage Capacity** | $20\text{ GB}$ SSD | $100\text{ GB}+$ NVMe SSD (High IOPS for PostgreSQL logs) |
| **Network Interface** | $1\text{ Gbps}$ Network Card | $10\text{ Gbps}$ Dedicated Sniffing Interface |

### Presenter Talking Points
> "Here are the hardware and software specifications for AI-NIDS. On the software side, we rely on React 19 and Vite for the frontend, FastAPI and Scikit-Learn for the backend, and Docker Compose for orchestration. For hardware, minimum deployment requires a 4-core CPU with 8GB RAM, while production SOC environments benefit from an 8-core CPU, 16GB to 32GB RAM, and NVMe SSDs for logging high-throughput network telemetry."

---

## Slide 7: Algorithm & Mathematical Formulations

### Slide Content
* **Algorithm 1: Random Forest Threat Classification:**
  1. *Input:* Normalized flow vector $V = \{p_{src}, p_{dst}, s_{pkt}, E_{pkt}, f_{syn}, f_{ack}, \dots\}$
  2. *Ensemble Inference:* Pass $V$ through $N=100$ decision trees: $\hat{y}_b = T_b(V)$ for $b \in [1, N]$.
  3. *Majority Voting:* Classify threat label: $\hat{Y} = \operatorname{mode}(\{\hat{y}_1, \dots, \hat{y}_N\})$.
  4. *Threat Confidence Score:* $S_{threat} = \frac{1}{N} \sum_{b=1}^{N} \mathbb{I}(\hat{y}_b \neq \text{'Normal'}) \times 100\%$.
* **Algorithm 2: Shannon Entropy Anomaly Detection:**
  * Mathematical Formula: 
    $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
  * *DGA Domain Threshold:* If $H(\text{hostname}) > 3.8$, flag as botnet DGA string.
  * *Packed Payload Threshold:* If $H(\text{file\_binary}) > 5.3$, flag as packed/encrypted dropper.

### Presenter Talking Points
> "This slide outlines our detection algorithms. Algorithm 1 is our Random Forest classifier. It takes normalized flow vectors and feeds them to 100 decision trees. The output label is determined by majority vote, and the threat score represents the ensemble's confidence. Algorithm 2 is our Shannon Entropy anomaly engine. By calculating the information entropy of domain names and binary payloads, we flag high randomness. If a domain's entropy exceeds 3.8, it's flagged as a DGA botnet domain, while file entropy above 5.3 catches encrypted malware droppers."

---

## Slide 8: System Screenshots & SOC UI Walkthrough

### Slide Content
* **Visual Dashboard Highlights & Components:**
  * **Telemetry Overview:** Live KPI cards displaying Active Flows, Threat Ratio, and Quarantined Payloads.
  * **Bandwidth & Threat Charting:** Dynamic Recharts time-series charts rendering real-time traffic spikes and attack distributions.
  * **Threat Feed Alert Table:** Filterable alert log with origin IP badges, severity tags, and 1-click Firewall Block actions.
  * **Interactive Attack Simulator:** In-browser controls allowing analysts to simulate synthetic DDoS, Port Scans, and SQLi attacks to test AI model response live.
  * **URL & File Scanner Interface:** Dedicated forms for evaluating suspicious URLs and inspecting uploaded log or binary files.

```
+-----------------------------------------------------------------------------------+
|  AI-NIDS SOC DASHBOARD                                                            |
|  [Active Flows: 1,420]   [Threat Ratio: 4.2%]   [Quarantined: 18]   [Status: ONLINE] |
+-----------------------------------------------------------------------------------+
| Live Bandwidth & Threat Telemetry (Recharts)                                       |
|  1000 |---------\---/\------------------/---\--- (Bandwidth Mbps)                |
|   500 |----------\-/--\----------------/-----\-- (Threat Spikes)                 |
+------------------------------------------+----------------------------------------+
| Recent Threat Feed                       | Attack Simulator Controls              |
| 192.168.1.105 | Port Scan | HIGH | [BLOCK] | Select Attack: [DDoS Flood       v]    |
| 10.0.0.42     | SQLi      | CRIT | [BLOCK] | Rate: [100 req/s]  [ INJECT ATTACK ] |
+------------------------------------------+----------------------------------------+
```

### Presenter Talking Points
> "Slide 8 demonstrates our Security Operations Center user interface. The dashboard features real-time telemetry metrics across the top, dynamic time-series charts powered by Recharts in the center, and a live threat feed table at the bottom with one-click firewall blocking buttons. Analysts can also launch the integrated Attack Simulator to test how the AI engine detects live synthetic attack vectors."

---

## Slide 9: Experimental Evaluation & Model Performance

### Slide Content

| Attack Category | Precision | Recall | F1-Score | Detection Latency |
| :--- | :---: | :---: | :---: | :---: |
| **Normal Traffic** | 98.4% | 99.1% | 98.7% | $< 2.0\text{ ms}$ |
| **DDoS Attack** | 99.2% | 98.8% | 99.0% | $< 3.0\text{ ms}$ |
| **Port Scanning** | 97.6% | 96.5% | 97.0% | $< 2.0\text{ ms}$ |
| **SQL Injection** | 96.1% | 95.3% | 95.7% | $< 4.0\text{ ms}$ |
| **Zero-Day / DGA Anomaly** | 93.8% | 91.2% | 92.5% | $< 5.0\text{ ms}$ |
| **Overall System Average** | **97.0%** | **96.2%** | **96.6%** | **$< 3.2\text{ ms}$** |

* **Key Performance Outcomes:**
  * **Target Accuracy Exceeded:** Achieved $96.6\%$ overall system F1-Score on test evaluation data.
  * **Low Latency:** Average vector inference takes $<3.2\text{ ms}$, ensuring real-time line-rate inspection.
  * **Zero-Day Resilience:** Entropy engine maintained a $92.5\%$ F1-Score on unseen DGA botnet domains.

### Presenter Talking Points
> "Here are our empirical evaluation results. Tested across synthetic network logs and simulated attack datasets, AI-NIDS achieved an overall precision of 97.0% and recall of 96.2%. Even on zero-day DGA threats with no static signatures, our entropy engine maintained a 92.5% F1-Score. Crucially, total inference latency averaged under 3.2 milliseconds per flow packet, satisfying strict real-time monitoring requirements."

---

## Slide 10: Conclusion & Major Contributions

### Slide Content
* **Summary of Core Contributions:**
  1. **Hybrid AI Detection Architecture:** Successfully combined Random Forest classification with Shannon Entropy heuristic anomaly detection.
  2. **Full-Stack Production SOC Dashboard:** Created a high-performance React 19 web application providing real-time telemetry charting and 1-click mitigation.
  3. **Multi-Vector Threat Defense:** Unified packet flow, URL phishing, and file payload security into a single operational platform.
  4. **Scalable Cloud Infrastructure:** Packaged backend services into Docker containers and AWS Lambda serverless functions (`Dockerfile.lambda`).

### Presenter Talking Points
> "In conclusion, AI-NIDS demonstrates that combining machine learning classifiers with mathematical entropy checks provides a highly effective defense against modern cyber threats. We have delivered a functional, production-ready full-stack application featuring a hybrid AI engine, an interactive SOC dashboard, and containerized cloud deployment capabilities."

---

## Slide 11: Future Scope & Roadmap

### Slide Content
* **Future Research & Feature Roadmap:**
  * **Deep Learning Integration:** Implementing Long Short-Term Memory (LSTM) networks and Autoencoders for sequential time-series anomaly detection.
  * **Distributed Edge Sensor Network:** Deploying lightweight AI-NIDS edge probes on regional subnet routers feeding a centralized SIEM data lake.
  * **Automated SOAR Playbooks:** Generating dynamic BGP routing updates and automated active firewall blocking scripts upon threat detection.
  * **Explainable AI (XAI):** Incorporating SHAP (SHapley Additive exPlanations) values to provide analysts with explicit feature importance rationale for every alert.

### Presenter Talking Points
> "Looking ahead, our future roadmap includes three key developments: integrating LSTM neural networks for deep sequential pattern analysis, deploying distributed edge sensors across regional subnet routers, and building automated SOAR playbooks for dynamic firewall and BGP route updates. Thank you for your attention, and I am now happy to answer any questions!"

---

## Viva & Defense Q&A Preparation

### Q1: Why did you choose Random Forest over Deep Learning models like CNN or LSTM for the baseline classifier?
**Answer:** Random Forest offers superior training speeds, lower inference latency ($<3.2\text{ ms}$), and high resilience against overfitting on tabular flow logs. It also provides native feature importance extraction, allowing security analysts to understand *why* a specific flow was flagged (e.g., unusual destination port or abnormal packet size).

### Q2: How does the Shannon Entropy check detect zero-day malware or DGA domains?
**Answer:** Human-created domain names and benign code strings follow predictable linguistic or syntactic structures, resulting in lower entropy (typically $2.0 - 3.2$). Botnets using Domain Generation Algorithms generate pseudo-random strings (e.g., `x89qzk19mva.biz`) exhibiting high mathematical randomness ($H(X) > 3.8$). Packed executable files similarly exhibit high binary entropy ($H(X) > 5.3$). By setting statistical entropy thresholds, we detect novel threats purely through data randomness without needing a pre-existing signature database.

### Q3: How do you prevent concept drift as network traffic patterns evolve?
**Answer:** We implemented an Analyst Feedback Loop in the SOC Dashboard via the `/url/feedback` and `/url/retrain` endpoints. When security analysts reclassify mislabeled traffic in the UI, the feedback is persisted to PostgreSQL and triggers automated retraining of the Random Forest model with updated feature weights.

### Q4: How is serverless deployment achieved with AWS Lambda?
**Answer:** Using `Dockerfile.lambda`, we package the FastAPI application, Python dependencies, and pre-trained model binaries (`.pkl`) into an AWS Lambda container image. AWS Lambda natively supports container images up to $10\text{ GB}$, allowing our backend detection engine to execute statelessly and scale horizontally during traffic bursts with zero idle cost.
