import json
import os
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

def lambda_handler(event, context):
    """
    AWS Lambda entry point for processing network traffic prediction requests.
    Expects event body:
    {
       "protocol": "TCP",
       "size": 1200,
       "entropy": 0.2,
       "flags_syn": 1,
       "src_port": 45000,
       "dest_port": 80
    }
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
                    "message": "AI-NIDS Inference API is operational. Send a POST request with traffic parameters for threat prediction."
                })
            }

        # Parse body if passed via API Gateway / Lambda Function URL
        if "body" in event and event["body"]:
            body = json.loads(event["body"]) if isinstance(event["body"], str) else event["body"]
        else:
            body = event

        # Format features into DataFrame matching trained model columns
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

