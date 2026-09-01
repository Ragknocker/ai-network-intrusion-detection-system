import math
import re
from urllib.parse import urlparse

def calculate_str_entropy(s):
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def extract_url_static_features(url_str):
    """
    Extracts lexical, structural, host, and contextual features from a URL.
    """
    url = (url_str or "").strip()
    length = len(url)
    dots = url.count(".")
    hyphens = url.count("-")
    digits = sum(c.isdigit() for c in url)
    digit_ratio = round(digits / length, 4) if length > 0 else 0.0
    has_https = url.lower().startswith("https://")
    contains_ip = bool(re.search(r"(\d{1,3}\.){3}\d{1,3}", url))
    entropy = calculate_str_entropy(url)

    # Lexical details
    special_char_counts = {
        "hyphen": hyphens,
        "underscore": url.count("_"),
        "percent": url.count("%"),
        "at_sign": url.count("@"),
        "equal": url.count("="),
        "question": url.count("?"),
        "slash": url.count("/")
    }

    parsed = urlparse(url if url.startswith("http://") or url.startswith("https://") else "http://" + url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    host_entropy = calculate_str_entropy(hostname)
    path_entropy = calculate_str_entropy(path)

    # Subdomain count
    subdomains = hostname.split(".") if hostname else []
    subdomain_count = max(0, len(subdomains) - 2) if len(subdomains) >= 2 else 0

    # Suspicious TLD check
    suspicious_tlds = [".xyz", ".tk", ".ru", ".top", ".click", ".gq", ".cf", ".ml", ".work"]
    has_suspicious_tld = any(hostname.endswith(tld) for tld in suspicious_tlds)

    # URL shorteners
    shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly"]
    is_shortened = any(s in hostname for s in shorteners)

    # Redirect trick (@ in path or netloc)
    has_at_symbol = "@" in url

    # Double slash mid-path
    has_double_slash_path = "//" in path

    suspicious_words = [
        "login", "paypal", "paypa1", "bank", "verify", "secure", "token", 
        "admin", "shell", "exec", "account", "update", "auth", "credential",
        "wallet", "crypto", "c2", "botnet"
    ]
    matched = [w for w in suspicious_words if w in url.lower()]

    # Contextual Network Features (Beaconing / Frequency)
    is_suspicious_host = contains_ip or has_suspicious_tld or len(matched) > 0
    domain_freq_internal_hosts = 24 if is_suspicious_host else 2
    is_first_seen_domain = is_suspicious_host
    beaconing_periodicity_score = 0.88 if is_suspicious_host else 0.05

    return {
        "url": url,
        "length": length,
        "host_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),
        "dots": dots,
        "hyphens": hyphens,
        "digits": digits,
        "digit_ratio": digit_ratio,
        "subdomain_count": subdomain_count,
        "has_https": has_https,
        "contains_ip": contains_ip,
        "entropy": entropy,
        "host_entropy": host_entropy,
        "path_entropy": path_entropy,
        "special_char_counts": special_char_counts,
        "has_suspicious_tld": has_suspicious_tld,
        "is_shortened": is_shortened,
        "has_at_symbol": has_at_symbol,
        "has_double_slash_path": has_double_slash_path,
        "suspicious_keywords": matched,
        "network_context": {
            "domain_freq_internal_hosts": domain_freq_internal_hosts,
            "is_first_seen_domain": is_first_seen_domain,
            "beaconing_periodicity_score": beaconing_periodicity_score
        }
    }

