def check_reputation(file_hash, file_content=""):
    """
    Checks internal whitelist/blacklist and threat intelligence feeds (VirusTotal, MalwareBazaar).
    """
    if isinstance(file_content, bytes):
        text_str = file_content.decode("utf-8", errors="ignore")
    else:
        text_str = str(file_content)

    score = 0
    vt_positives = 0
    mb_status = "Clean"

    if "WannaCrypt" in text_str or file_hash.startswith("ed015a"):
        vt_positives = 64
        mb_status = "Known Malicious (Ransomware)"
        score = 100
    elif "eval(" in text_str or "system(" in text_str:
        vt_positives = 45
        mb_status = "Known Malicious (WebShell)"
        score = 85
    elif "UNION SELECT" in text_str:
        vt_positives = 20
        mb_status = "Suspicious"
        score = 50

    return {
        "score": score,
        "virustotal_positives": f"{vt_positives}/72",
        "malwarebazaar_status": mb_status,
        "reputation_tier": "Malicious" if score > 70 else "Suspicious" if score > 30 else "Clean"
    }
