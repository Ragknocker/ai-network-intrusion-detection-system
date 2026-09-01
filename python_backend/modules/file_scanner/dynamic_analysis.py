def run_sandbox_analysis(file_content, filename=""):
    """
    Simulates dynamic sandbox execution tracing file creation, registry tweaks, processes, and network socket calls.
    """
    if isinstance(file_content, bytes):
        text_str = file_content.decode("utf-8", errors="ignore")
    else:
        text_str = str(file_content)

    events = []
    score = 0

    if "WannaCrypt" in text_str or filename.endswith(".exe"):
        events.append({"time": "0.01s", "type": "PROCESS", "detail": "Spawned sub-process cmd.exe /c vssadmin.exe Delete Shadows /All /Quiet"})
        events.append({"time": "0.04s", "type": "REGISTRY", "detail": "Modified HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WanaCrypt"})
        events.append({"time": "0.12s", "type": "NETWORK", "detail": "Outbound TCP connection to C2 IP 192.168.1.100:4444"})
        score = 95
    elif "eval(" in text_str or "system(" in text_str:
        events.append({"time": "0.02s", "type": "PROCESS", "detail": "WebShell invoked /bin/sh via CGI handler"})
        events.append({"time": "0.05s", "type": "NETWORK", "detail": "Established reverse shell socket to remote port 4444"})
        score = 80
    else:
        events.append({"time": "0.01s", "type": "PROCESS", "detail": "Executed cleanly without sub-process creation"})
        events.append({"time": "0.05s", "type": "NETWORK", "detail": "Zero network calls recorded"})
        score = 0

    return {
        "score": score,
        "events": events,
        "sandbox_environment": "Docker VM Sandbox"
    }
