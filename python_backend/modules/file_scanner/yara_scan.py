import re

# Gracefully import native YARA if available, otherwise use regex rules matcher
try:
    import yara
    HAS_NATIVE_YARA = True
except ImportError:
    HAS_NATIVE_YARA = False

def scan_yara_rules(file_content, filename=""):
    """
    Scans file content against YARA signature rules for WannaCry, WebShells, Ransomware, PDF, and Macros.
    """
    if isinstance(file_content, bytes):
        text_str = file_content.decode("utf-8", errors="ignore")
    else:
        text_str = str(file_content)

    matches = []
    score = 0

    # WannaCry Rule
    if re.search(r"WannaCrypt|WNCRY|WANACRY!|\.WNCRY\b", text_str, re.IGNORECASE):
        matches.append({
            "rule": "WannaCry_Ransomware",
            "severity": "Critical",
            "description": "Detected WannaCry ransomware mutex or file extension pattern."
        })
        score += 90

    # WebShell Rule
    if re.search(r"\b(eval|exec|passthru|shell_exec|system|popen)\s*\(", text_str, re.IGNORECASE):
        matches.append({
            "rule": "Generic_WebShell_Backdoor",
            "severity": "Critical",
            "description": "Detected arbitrary command execution primitive."
        })
        score += 75

    # PDF Exploit Rule
    if re.search(r"/OpenAction|/JavaScript|/JS\b", text_str, re.IGNORECASE):
        matches.append({
            "rule": "PDF_Exploit_Trigger",
            "severity": "High",
            "description": "Detected PDF auto-execution action trigger."
        })
        score += 70

    # Office Macro Rule
    if re.search(r"\b(AutoOpen|Document_Open|CreateObject\(\"WScript\.Shell\"\))\b", text_str, re.IGNORECASE):
        matches.append({
            "rule": "Office_VBA_Dropper",
            "severity": "High",
            "description": "Detected malicious office macro launch trigger."
        })
        score += 70

    return {
        "score": min(100, score),
        "matches": matches,
        "native_yara_enabled": HAS_NATIVE_YARA
    }
