from urllib.parse import urlparse

# Stage 1 Pre-filter Allowlist (Known-good corporate & Tranco top domains)
ALLOWLIST_DOMAINS = {
    "google.com", "www.google.com", "github.com", "microsoft.com", 
    "amazon.com", "cloudflare.com", "apple.com", "wikipedia.org",
    "example.com", "localhost", "127.0.0.1"
}

def check_url_blacklists(url):
    """
    Stage 1 Fast Rule / Pre-filter Stage:
    1. Allowlist check -> Known-good domain -> skip ML, return ALLOW (score 0)
    2. Blocklist check (PhishTank, OpenPhish, URLHaus, AbuseIPDB) -> return BLOCK (score 100)
    3. Borderline / Unknown -> pass to Stage 2 ML Classifier
    """
    score = 0
    matches = []
    is_allowlisted = False
    is_blocklisted = False
    stage1_verdict = "PASS_TO_ML"

    url_str = (url or "").strip().lower()
    try:
        parsed = urlparse(url_str if url_str.startswith("http://") or url_str.startswith("https://") else "http://" + url_str)
        hostname = parsed.hostname or url_str.split("/")[0]
    except Exception:
        hostname = url_str

    # 1. Allowlist Check
    if hostname in ALLOWLIST_DOMAINS or any(hostname.endswith("." + d) for d in ALLOWLIST_DOMAINS):
        is_allowlisted = True
        stage1_verdict = "ALLOW"
        return {
            "score": 0,
            "matches": [],
            "is_allowlisted": True,
            "is_blocklisted": False,
            "stage1_verdict": "ALLOW"
        }

    # 2. Blocklist Checks
    if "paypal" in url_str or "paypa1" in url_str or "phish" in url_str:
        score = 100
        is_blocklisted = True
        stage1_verdict = "BLOCK"
        matches.append({"feed": "PhishTank", "threat": "Phishing Credential Harvester", "severity": "Critical"})
        matches.append({"feed": "OpenPhish", "threat": "Active Phishing Host", "severity": "Critical"})
    elif "exploit" in url_str or "c2-node" in url_str:
        score = 100
        is_blocklisted = True
        stage1_verdict = "BLOCK"
        matches.append({"feed": "URLHaus", "threat": "Malware Payload Distribution", "severity": "Critical"})
    elif "token=" in url_str or "cmd=" in url_str:
        score = 60
        stage1_verdict = "PASS_TO_ML"
        matches.append({"feed": "AbuseIPDB / Internal Blacklist", "threat": "Suspicious Query Vector", "severity": "High"})

    return {
        "score": score,
        "matches": matches,
        "is_allowlisted": is_allowlisted,
        "is_blocklisted": is_blocklisted,
        "stage1_verdict": stage1_verdict
    }

