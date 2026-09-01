from .metadata import extract_file_metadata
from .static_analysis import perform_static_analysis
from .yara_scan import scan_yara_rules
from .signature_scan import scan_signatures
from .feature_extractor import extract_ai_feature_vector
from .ai_scan import classify_file_ai
from .reputation import check_reputation
from .dynamic_analysis import run_sandbox_analysis
from .quarantine import quarantine_file_backend

class FileThreatScannerEngine:
    def __init__(self):
        pass

    def scan_file(self, file_content, filename="unnamed_file"):
        # Step 1 & 2: Metadata & Hash Generation
        meta = extract_file_metadata(file_content, filename)

        # Step 3: Signature Scanning
        sig_res = scan_signatures(meta["sha256"], file_content)

        # Step 4: YARA Rules Scan
        yara_res = scan_yara_rules(file_content, filename)

        # Step 5: Static Feature Analysis
        static_res = perform_static_analysis(file_content, filename)

        # Step 6: AI Feature Extraction
        vector = extract_ai_feature_vector(meta, static_res, yara_res, sig_res)

        # Step 7: AI Malware Classification
        ai_res = classify_file_ai(vector, file_content)

        # Step 8: Reputation Lookup
        rep_res = check_reputation(meta["sha256"], file_content)

        # Step 9: Dynamic Sandbox Execution
        sb_res = run_sandbox_analysis(file_content, filename)

        # Step 10: Threat Score Formula Calculation
        # Threat Score = 0.40 * AI + 0.25 * Signature + 0.15 * Sandbox + 0.10 * Reputation + 0.10 * YARA
        raw_score = round(
            (ai_res["score"] * 0.40) +
            (sig_res["score"] * 0.25) +
            (sb_res["score"] * 0.15) +
            (rep_res["score"] * 0.10) +
            (yara_res["score"] * 0.10)
        )
        threat_score = min(100, max(0, raw_score))

        # Step 11: 4-Tier Decision Engine
        if threat_score > 80:
            decision = "BLOCK + ALERT"
            status = "Critical Malicious"
            disposition = "CRITICAL - BLOCK & ALERT SOC"
        elif threat_score > 60:
            decision = "QUARANTINE"
            status = "Threat / Malicious"
            disposition = "UNSAFE - QUARANTINE / DELETE IMMEDIATELY"
        elif threat_score > 30:
            decision = "MONITOR"
            status = "Suspicious"
            disposition = "SUSPICIOUS - AUDIT BEFORE RETENTION"
        else:
            decision = "ALLOW"
            status = "Safe / Clean"
            disposition = "SAFE TO KEEP"

        # Step 12: Automated Quarantine
        quarantine_info = None
        if decision in ["QUARANTINE", "BLOCK + ALERT"]:
            quarantine_info = quarantine_file_backend(filename, file_content, threat_score, meta["sha256"])

        return {
            "metadata": meta,
            "threat_score": threat_score,
            "decision": decision,
            "status": status,
            "disposition": disposition,
            "engine_breakdown": {
                "ai_score": ai_res["score"],
                "signature_score": sig_res["score"],
                "sandbox_score": sb_res["score"],
                "reputation_score": rep_res["score"],
                "yara_score": yara_res["score"]
            },
            "yara_matches": yara_res["matches"],
            "signatures": sig_res["signatures"],
            "sandbox_events": sb_res["events"],
            "quarantine_info": quarantine_info
        }
