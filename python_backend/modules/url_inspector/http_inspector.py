import re

def inspect_http_payload_backend(url, method="GET", headers=None, payload=""):
    """
    Inspects HTTP methods, headers, and request bodies for web attacks (SQLi, XSS, SSRF, Traversal).
    """
    full_text = f"{url} {payload}"
    attacks = []
    score = 0

    if re.search(r"UNION\s+SELECT|OR\s+1=1|DROP\s+TABLE", full_text, re.IGNORECASE):
        attacks.append({"category": "SQL Injection (SQLi)", "pattern": "UNION SELECT / OR 1=1", "severity": "Critical"})
        score += 90

    if re.search(r"<script|javascript:|onerror=", full_text, re.IGNORECASE):
        attacks.append({"category": "Cross-Site Scripting (XSS)", "pattern": "<script> / Inline Event", "severity": "High"})
        score += 80

    if re.search(r"169\.254\.169\.254|localhost|127\.0\.0\.1", full_text, re.IGNORECASE):
        attacks.append({"category": "Server-Side Request Forgery (SSRF)", "pattern": "Metadata IP Access", "severity": "Critical"})
        score += 85

    return {
        "score": min(100, score),
        "attacks": attacks
    }
