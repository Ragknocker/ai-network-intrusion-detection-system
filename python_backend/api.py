from modules.file_scanner.scanner import FileThreatScannerEngine
from modules.file_scanner.quarantine import list_quarantined_files
from modules.url_inspector.url_capture import capture_and_parse_url, normalize_url
from modules.url_inspector.url_features import extract_url_static_features
from modules.url_inspector.blacklist_checker import check_url_blacklists
from modules.url_inspector.domain_intelligence import get_domain_intel_backend
from modules.url_inspector.ml_url_classifier import classify_url_ml_backend
from modules.url_inspector.http_inspector import inspect_http_payload_backend
from modules.url_inspector.feedback_retrainer import record_analyst_feedback, trigger_model_retraining, calculate_model_drift, get_feedback_history
from modules.function_inspector.api_monitor import monitor_system_call_backend
import time

scanner_engine = FileThreatScannerEngine()

def handle_api_request(endpoint, method="GET", payload=None):
    """
    FastAPI router simulation exposing required REST endpoints.
    """
    if endpoint == "/scan/file" and method == "POST":
        file_content = payload.get("content", "") if payload else ""
        filename = payload.get("filename", "uploaded_file.bin") if payload else "uploaded_file.bin"
        result = scanner_engine.scan_file(file_content, filename)
        return {"status_code": 200, "data": result}

    elif endpoint == "/scan/network-file" and method == "POST":
        file_content = payload.get("content", "") if payload else ""
        filename = payload.get("filename", "network_file.pcap") if payload else "network_file.pcap"
        result = scanner_engine.scan_file(file_content, filename)
        return {"status_code": 200, "source": "Network Packet Capture", "data": result}

    elif endpoint == "/url/extract" and method == "POST":
        url = payload.get("url", "") if payload else ""
        proto = payload.get("source_protocol", "HTTP/1.1") if payload else "HTTP/1.1"
        event = capture_and_parse_url(url, source_protocol=proto)
        return {"status_code": 200, "extracted_event": event}

    elif endpoint == "/scan/url" and method == "POST":
        url = payload.get("url", "http://example.com") if payload else "http://example.com"
        proto = payload.get("source_protocol", "HTTP/1.1") if payload else "HTTP/1.1"
        
        extracted = capture_and_parse_url(url, source_protocol=proto)
        feats = extract_url_static_features(extracted["normalized_url"])
        bl = check_url_blacklists(extracted["normalized_url"])
        domain_intel = get_domain_intel_backend(extracted["hostname"])

        # Stage 1 Pre-filter logic
        if bl.get("is_allowlisted"):
            ml = {
                "score": 0,
                "phishing_probability": 0.0,
                "model": "Stage 1 Pre-Filter Allowlist",
                "reasons": ["Domain matches trusted corporate / Tranco allowlist"],
                "disposition": "SAFE / CLEAN DOMAIN",
                "decision": "ALLOW"
            }
        elif bl.get("is_blocklisted"):
            ml = {
                "score": 100,
                "phishing_probability": 1.0,
                "model": "Stage 1 Pre-Filter Blocklist",
                "reasons": ["Domain matches known active threat intelligence blocklist feed"],
                "disposition": "CRITICAL KNOWN THREAT",
                "decision": "BLOCK"
            }
        else:
            ml = classify_url_ml_backend(feats)

        return {
            "status_code": 200,
            "url": url,
            "extracted_event": extracted,
            "features": feats,
            "blacklist": bl,
            "domain_intel": domain_intel,
            "ai_classification": ml,
            "siem_event_payload": {
                "timestamp": extracted["timestamp"],
                "src_ip": extracted["src_ip"],
                "dst_ip": extracted["dst_ip"],
                "url": url,
                "normalized_url": extracted["normalized_url"],
                "source_protocol": proto,
                "threat_score": max(bl["score"], ml["score"]),
                "verdict": ml.get("decision", "ALLOW"),
                "reasons": ml.get("reasons", [])
            }
        }

    elif endpoint == "/url/feedback" and method == "POST":
        url = payload.get("url", "") if payload else ""
        score = payload.get("predicted_score", 0) if payload else 0
        verdict = payload.get("analyst_verdict", "Confirmed Malicious") if payload else "Confirmed Malicious"
        comments = payload.get("comments", "") if payload else ""
        res = record_analyst_feedback(url, score, verdict, comments)
        return {"status_code": 200, "feedback": res}

    elif endpoint == "/url/feedback" and method == "GET":
        history = get_feedback_history()
        return {"status_code": 200, "feedback_history": history}

    elif endpoint == "/url/retrain" and method == "POST":
        res = trigger_model_retraining()
        return {"status_code": 200, "retrain_result": res}

    elif endpoint == "/url/drift" and method == "GET":
        drift = calculate_model_drift()
        return {"status_code": 200, "model_drift": drift}

    elif endpoint == "/scan/function-event" and method == "POST":
        func_name = payload.get("func_name", "VirtualAlloc") if payload else "VirtualAlloc"
        process_name = payload.get("process_name", "cmd.exe") if payload else "cmd.exe"
        res = monitor_system_call_backend(func_name, process_name)
        return {"status_code": 200, "function_event": res}

    elif endpoint.startswith("/scan/result/") and method == "GET":
        scan_id = endpoint.split("/")[-1]
        return {
            "status_code": 200,
            "scan_id": scan_id,
            "result": "Scan result fetched from audit log database"
        }

    elif endpoint == "/quarantine" and method == "GET":
        items = list_quarantined_files()
        return {"status_code": 200, "quarantined_files": items, "count": len(items)}

    elif endpoint == "/quarantine/restore" and method == "POST":
        quarantine_id = payload.get("id") if payload else None
        return {"status_code": 200, "restored": True, "id": quarantine_id}

    elif endpoint == "/threats" and method == "GET":
        return {
            "status_code": 200,
            "recent_threats": [
                {"rule": "WannaCry_Ransomware", "type": "Ransomware", "risk": "Critical"},
                {"rule": "Generic_WebShell_Backdoor", "type": "WebShell", "risk": "Critical"}
            ]
        }

    elif endpoint == "/threats/url" and method == "GET":
        return {
            "status_code": 200,
            "url_threats": [
                {"url": "http://secure-paypal-login.xyz", "threat": "Phishing", "severity": "Critical"},
                {"url": "http://c2-node-server.ru/exploit.exe", "threat": "Malware Payload", "severity": "Critical"}
            ]
        }

    elif endpoint == "/dashboard/file-threats" and method == "GET":
        return {
            "status_code": 200,
            "summary": {
                "total_scanned": 154,
                "safe_files": 128,
                "suspicious_files": 14,
                "malicious_files": 12,
                "quarantined_count": 12
            },
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }

    elif endpoint == "/dashboard/url-threats" and method == "GET":
        return {
            "status_code": 200,
            "summary": {
                "total_urls_scanned": 842,
                "malicious_urls": 42,
                "phishing_attempts": 28,
                "blocked_connections": 42
            },
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }

    return {"status_code": 404, "error": f"Endpoint {endpoint} not found"}

