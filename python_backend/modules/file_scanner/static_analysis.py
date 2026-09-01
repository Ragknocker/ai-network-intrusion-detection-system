import math
import re

def calculate_entropy(data_bytes):
    """
    Calculates Shannon Entropy of a byte sequence (0.0 to 8.0).
    """
    if not data_bytes:
        return 0.0
    entropy = 0.0
    length = len(data_bytes)
    freq = {}
    for byte in data_bytes:
        freq[byte] = freq.get(byte, 0) + 1
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def perform_static_analysis(file_content, filename=""):
    """
    Performs static feature extraction on PE binaries, PDFs, Office documents, and scripts.
    """
    if isinstance(file_content, str):
        raw_bytes = file_content.encode("utf-8", errors="ignore")
        text_str = file_content
    else:
        raw_bytes = file_content
        text_str = file_content.decode("utf-8", errors="ignore")

    entropy = calculate_entropy(raw_bytes)
    ext = filename.split(".")[-1].lower() if "." in filename else ""

    features = {
        "entropy": entropy,
        "is_high_entropy": entropy > 5.3,
        "suspicious_apis": [],
        "has_pe_header": raw_bytes.startswith(b"MZ"),
        "has_pdf_header": raw_bytes.startswith(b"%PDF-"),
        "macro_indicators": [],
        "obfuscated_lines": 0
    }

    # Code API inspection
    api_patterns = [
        (r"\b(eval|exec|passthru|shell_exec|system|popen)\s*\(", "Code Execution Primitive"),
        (r"\b(base64_decode|gzinflate|hex2bin|String\.fromCharCode)\s*\(", "Obfuscation Decoder"),
        (r"\b(nc|netcat|nmap|cmd\.exe|powershell|-e\s+sh)\b", "Reverse Shell Binary"),
        (r"UNION\s+SELECT|OR\s+1=1", "SQL Exploit Payload"),
        (r"/OpenAction|/JavaScript|/JS\b", "PDF Exploit Trigger"),
        (r"\b(AutoOpen|Document_Open|CreateObject)\b", "VBA Macro AutoOpen")
    ]

    for pattern, name in api_patterns:
        if re.search(pattern, text_str, re.IGNORECASE):
            features["suspicious_apis"].append(name)

    if "/OpenAction" in text_str or "/JavaScript" in text_str:
        features["macro_indicators"].append("PDF AutoExecute Object")

    if "AutoOpen" in text_str or "Document_Open" in text_str:
        features["macro_indicators"].append("Office VBA AutoOpen Macro")

    return features
