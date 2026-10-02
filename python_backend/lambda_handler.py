import json
import os
import re
import math
import joblib
import pandas as pd
import numpy as np

# Optional DB logging support
try:
    import psycopg2
except ImportError:
    psycopg2 = None

# Load pre-trained Random Forest model
MODEL_PATH = os.path.join(os.path.dirname(__file__), "rf_nids_model.pkl")

model = None
if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)

def calculate_shannon_entropy(text):
    """Calculates Shannon entropy of a given text string."""
    if not text:
        return 0.0
    frequencies = {}
    for char in text:
        frequencies[char] = frequencies.get(char, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 2)

def analyze_url(url_str):
    """Heuristic Python analysis for URL legitimacy and phishing risk."""
    if not url_str:
        return {"status": "Unknown", "threatScore": 0, "riskFactors": []}
    
    url = url_str.strip().lower()
    risk_score = 5
    risk_factors = []

    # Check protocol
    if not url.startswith("https://"):
        risk_score += 15
        risk_factors.append("Unencrypted HTTP or missing SSL protocol")

    # Extract hostname
    clean_url = re.sub(r"^https?://", "", url)
    hostname = clean_url.split("/")[0].split(":")[0]

    # IP Hostname check
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", hostname):
        risk_score += 30
        risk_factors.append("Raw IP hostname used instead of domain")

    # High risk TLD
    suspicious_tlds = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.zip', '.work', '.ru', '.cn']
    if any(hostname.endswith(tld) for tld in suspicious_tlds):
        risk_score += 25
        risk_factors.append("High-risk TLD detected")

    # Typosquatting
    typosquat_patterns = ['paypa1', 'g00gle', 'arnazon', 'micros0ft', 'faceb00k', 'app1e']
    if any(p in hostname for p in typosquat_patterns):
        risk_score += 30
        risk_factors.append("Typosquatting brand spoofing detected")

    # Entropy
    entropy = calculate_shannon_entropy(hostname)
    if entropy > 3.8:
        risk_score += 20
        risk_factors.append(f"High domain entropy ({entropy}) - Suspected DGA")

    threat_score = min(100, risk_score)
    status = "Legitimate"
    if threat_score > 65:
        status = "Phishing / Malicious"
    elif threat_score > 30:
        status = "Suspicious"

    return {
        "status": status,
        "threatScore": threat_score,
        "entropy": entropy,
        "riskFactors": risk_factors
    }

def analyze_code_payload(code_str):
    """Heuristic Python analysis for malicious functions in code/payloads."""
    if not code_str:
        return {"status": "Clean Code", "threatScore": 0, "flagged": []}
    
    code = code_str.strip()
    risk_score = 0
    flagged = []

    patterns = [
        (r"\b(eval|exec|passthru|shell_exec|system|popen)\s*\(", "Arbitrary Code Execution / RCE"),
        (r"\b(btoa|atob|base64_decode|gzinflate|hex2bin)\s*\(", "Obfuscated WebShell Payload"),
        (r"(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\s+.*(\+|\${|\.\s*['\"]|OR\s+1=1)", "SQL Injection Pattern"),
        (r"\b(document\.write|dangerouslySetInnerHTML|\.innerHTML\s*=)", "DOM XSS Injection")
    ]

    for pattern, desc in patterns:
        if re.search(pattern, code, re.IGNORECASE):
            risk_score += 30
            flagged.append(desc)

    entropy = calculate_shannon_entropy(code)
    if entropy > 4.8 and len(code) > 50:
        risk_score += 20
        flagged.append(f"High code payload entropy ({entropy})")

    threat_score = min(100, risk_score)
    status = "Clean Code"
    if threat_score >= 60:
        status = "Malicious Function / Exploit"
    elif threat_score > 20:
        status = "Suspicious Function"

    return {
        "status": status,
        "threatScore": threat_score,
        "entropy": entropy,
        "flagged": flagged
    }

def log_alert_to_db(classification, threat_score, is_threat, payload):
    """Logs threat prediction records into PostgreSQL database if DB_URL is configured."""
    db_url = os.environ.get("DB_URL")
    if not db_url or psycopg2 is None:
        return

    try:
        conn = psycopg2.connect(db_url)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS threat_alerts (
                id SERIAL PRIMARY KEY,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                classification VARCHAR(50),
                threat_score FLOAT,
                is_threat BOOLEAN,
                payload JSONB
            );
        """)
        cur.execute("""
            INSERT INTO threat_alerts (classification, threat_score, is_threat, payload)
            VALUES (%s, %s, %s, %s);
        """, (str(classification), float(threat_score), bool(is_threat), json.dumps(payload)))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as db_err:
        print(f"Warning: Failed to log to database: {db_err}")

def analyze_file_threat(file_name, file_content):
    """Python analysis for file upload threats and safe-to-keep disposition."""
    name = (file_name or "file.txt").lower()
    content = (file_content or "").strip()
    risk_score = 5
    flagged = []

    if name.endswith(('.php', '.js', '.py', '.sh', '.html')):
        patterns = [
            (r"\b(eval|exec|passthru|shell_exec|system|popen)\s*\(", "WebShell / Remote Code Execution"),
            (r"\b(btoa|atob|base64_decode|gzinflate|hex2bin)\s*\(", "Obfuscated Script Payload"),
            (r"(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\s+.*(\+|\${|\.\s*['\"]|OR\s+1=1)", "SQL Injection Concatenation"),
            (r"\b(nc|netcat|nmap|cmd\.exe|powershell|-e\s+sh|\/bin\/bash)\b", "Reverse Shell Binary Call")
        ]
        for pattern, desc in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                risk_score += 35
                flagged.append(desc)

    elif name.endswith(('.csv', '.log', '.pcap')):
        if re.search(r"(DDoS|UDP\s+Flood|SYN\s+Flood|HTTP\s+GET\s+Flood)", content, re.IGNORECASE):
            risk_score += 35
            flagged.append("DDoS Flood Log Entry")
        if re.search(r"(SYN-Stealth|Nmap\s+Script\s+Engine|Port\s+Scan)", content, re.IGNORECASE):
            risk_score += 25
            flagged.append("Reconnaissance Port Scan Log")

    elif name.endswith(('.exe', '.dll', '.bin', '.bat', '.ps1')):
        risk_score += 20
        flagged.append("Executable Binary Execution Risk")

    entropy = calculate_shannon_entropy(content)
    if entropy > 5.3 and len(content) > 50:
        risk_score += 25
        flagged.append(f"High File Entropy ({entropy}) - Suspected Encrypted Dropper")

    threat_score = min(100, risk_score)
    status = "Safe / Clean"
    disposition = "SAFE TO KEEP"
    if threat_score > 65:
        status = "Threat / Malicious"
        disposition = "UNSAFE - QUARANTINE / DELETE IMMEDIATELY"
    elif threat_score > 25:
        status = "Suspicious"
        disposition = "SUSPICIOUS - AUDIT BEFORE RETENTION"

    return {
        "fileName": file_name,
        "threatScore": threat_score,
        "status": status,
        "disposition": disposition,
        "entropy": entropy,
        "flagged": flagged
    }

def lambda_handler(event, context):
    """
    AWS Lambda entry point for network traffic, URL/Function, and File Upload prediction requests.
    """
    try:
        # Check HTTP method if triggered via API Gateway or Function URL
        http_method = event.get("httpMethod") or event.get("requestContext", {}).get("http", {}).get("method", "POST")
        
        # 1. Handle CORS Preflight OPTIONS Request
        if http_method == "OPTIONS":
            return {
                "statusCode": 200,
                "headers": {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Headers": "Content-Type,Authorization",
                    "Access-Control-Allow-Methods": "OPTIONS,POST,GET"
                },
                "body": json.dumps({"status": "ok"})
            }

        # 2. Handle GET request (Health Check)
        if http_method == "GET":
            return {
                "statusCode": 200,
                "headers": {
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "*"
                },
                "body": json.dumps({
                    "status": "online",
                    "message": "AI-NIDS Inference API is operational. Supports network flow, URL legitimacy, code function, and file upload threat scanning."
                })
            }

        # Parse body if passed via API Gateway / Lambda Function URL
        if "body" in event and event["body"]:
            body = json.loads(event["body"]) if isinstance(event["body"], str) else event["body"]
        else:
            body = event

        # Check if File analysis is requested
        if "file_content" in body or "file_name" in body:
            file_res = analyze_file_threat(body.get("file_name", "uploaded_file.txt"), body.get("file_content", ""))
            return {
                "statusCode": 200,
                "headers": {
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "*"
                },
                "body": json.dumps({
                    "status": "success",
                    "targetType": "FileUpload",
                    "analysis": file_res
                })
            }

        # Check if URL analysis is requested
        if "url" in body:
            url_res = analyze_url(body["url"])
            return {
                "statusCode": 200,
                "headers": {
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "*"
                },
                "body": json.dumps({
                    "status": "success",
                    "targetType": "URL",
                    "analysis": url_res
                })
            }

        # Check if Code Payload analysis is requested
        if "code_payload" in body:
            code_res = analyze_code_payload(body["code_payload"])
            return {
                "statusCode": 200,
                "headers": {
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "*"
                },
                "body": json.dumps({
                    "status": "success",
                    "targetType": "CodePayload",
                    "analysis": code_res
                })
            }

        # Standard Network Flow prediction
        sample_data = {
            'src_port': [body.get('src_port', 1024)],
            'dest_port': [body.get('dest_port', 80)],
            'size': [body.get('size', 500)],
            'entropy': [body.get('entropy', 0.5)],
            'flags_syn': [body.get('flags_syn', 1)],
            'protocol_ICMP': [1 if body.get('protocol') == 'ICMP' else 0],
            'protocol_TCP': [1 if body.get('protocol') == 'TCP' else 0],
            'protocol_UDP': [1 if body.get('protocol') == 'UDP' else 0]
        }

        df = pd.DataFrame(sample_data)

        if model is not None:
            prediction = model.predict(df)[0]
            probabilities = model.predict_proba(df)[0]
            confidence = float(np.max(probabilities) * 100)
        else:
            prediction = "Normal"
            confidence = 95.0

        is_threat = bool(prediction != "Normal")
        threat_score = round(confidence, 2)

        # Log prediction alert to PostgreSQL database if configured
        log_alert_to_db(prediction, threat_score, is_threat, body)

        response_body = {
            "status": "success",
            "classification": str(prediction),
            "threatScore": threat_score,
            "isThreat": is_threat
        }

        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Headers": "Content-Type",
                "Access-Control-Allow-Methods": "OPTIONS,POST,GET"
            },
            "body": json.dumps(response_body)
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*"
            },
            "body": json.dumps({"status": "error", "message": str(e)})
        }
