def scan_signatures(file_hash, file_content):
    """
    Simulates ClamAV & known virus signature database checking.
    """
    if isinstance(file_content, bytes):
        text_str = file_content.decode("utf-8", errors="ignore")
    else:
        text_str = str(file_content)

    signatures = []
    score = 0

    known_hashes = [
        "ed015a5404e1575312226e370d857f17b5e6841500f483c773e7f2254a4c28d2",
        "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    ]

    if file_hash in known_hashes:
        score = 100
        signatures.append("ClamAV: Win.Ransomware.WannaCry-1")

    if "WannaCrypt" in text_str:
        score = max(score, 90)
        signatures.append("ClamAV: Win.Ransomware.WannaCry-Generic")
    elif "eval(" in text_str or "system(" in text_str:
        score = max(score, 80)
        signatures.append("ClamAV: PHP.WebShell.Generic-99")
    elif "UNION SELECT" in text_str or "DDoS" in text_str:
        score = max(score, 60)
        signatures.append("ClamAV: Exploit.HTTP.Payload-14")

    return {
        "score": score,
        "signatures": signatures,
        "clamav_status": "Active / Updated"
    }
