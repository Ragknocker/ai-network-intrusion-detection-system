import time

# In-memory feedback store and drift history
_analyst_feedback_store = []
_score_history = [12, 18, 5, 8, 42, 65, 88, 92, 14, 22, 55, 78, 95, 8, 11]

def record_analyst_feedback(url, predicted_score, analyst_verdict, comments=""):
    """
    Records an analyst disposition (Confirmed Malicious, False Positive, Benign).
    """
    entry = {
        "id": f"fb-{len(_analyst_feedback_store) + 1:04d}",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "url": url,
        "predicted_score": predicted_score,
        "analyst_verdict": analyst_verdict,
        "comments": comments
    }
    _analyst_feedback_store.append(entry)
    return {"status": "success", "recorded_entry": entry, "total_feedback_samples": len(_analyst_feedback_store)}

def get_feedback_history():
    return _analyst_feedback_store

def trigger_model_retraining():
    """
    Simulates a periodic retraining pipeline run using analyst labeled data.
    """
    return {
        "status": "completed",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "new_model_version": "XGBoost URL Classifier v2.5-retrained",
        "training_samples_used": 1420 + len(_analyst_feedback_store),
        "validation_accuracy": 0.9884,
        "validation_f1_score": 0.9812,
        "message": "Model retrained successfully with updated analyst feedback and threat intelligence feeds."
    }

def calculate_model_drift():
    """
    Monitors score distribution drift over time.
    """
    bins = {f"{i*10}-{(i+1)*10}": 0 for i in range(10)}
    for s in _score_history:
        b_idx = min(9, s // 10)
        bin_key = f"{b_idx*10}-{(b_idx+1)*10}"
        bins[bin_key] = bins.get(bin_key, 0) + 1

    total = max(1, len(_score_history))
    mean_score = round(sum(_score_history) / total, 2)
    high_threat_ratio = round(sum(1 for s in _score_history if s > 70) / total, 4)

    drift_status = "STABLE" if high_threat_ratio < 0.4 else "DRIFT DETECTED"

    return {
        "total_evaluated": total,
        "mean_risk_score": mean_score,
        "high_threat_ratio": high_threat_ratio,
        "drift_status": drift_status,
        "score_distribution": bins
    }
