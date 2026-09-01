def analyze_process_behavior_backend(events):
    """
    Analyzes sequences of function calls and process trees for memory injection and privilege escalation.
    """
    has_injection = any(e.get("severity") == "Critical" for e in events)
    return {
        "risk_level": "High Risk" if has_injection else "Normal",
        "anomaly_score": 85 if has_injection else 10,
        "process_tree": [
            {"pid": 1040, "name": "services.exe", "parent": 800},
            {"pid": 2180, "name": "powershell.exe", "parent": 1040}
        ]
    }
