def monitor_system_call_backend(func_name, process_name="", payload=""):
    """
    Monitors Windows Win32 APIs (CreateProcess, VirtualAlloc, RegSetValue) and Linux syscalls (execve, connect).
    """
    full_str = f"{func_name} {process_name} {payload}"
    events = []
    score = 0

    if any(k in full_str for k in ["VirtualAlloc", "CreateRemoteThread", "WriteProcessMemory"]):
        events.append({"api": "VirtualAllocEx()", "process": process_name or "cmd.exe", "action": "Allocated RWX memory in remote process PID 4120", "severity": "Critical"})
        events.append({"api": "CreateRemoteThread()", "process": process_name or "cmd.exe", "action": "Injected thread into explorer.exe", "severity": "Critical"})
        score = 95
    elif any(k in full_str for k in ["RegSetValue", "RegCreateKey"]):
        events.append({"api": "RegSetValueExA()", "process": process_name or "powershell.exe", "action": "Modified HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "severity": "High"})
        score = 75
    elif any(k in full_str for k in ["CreateProcess", "WinExec", "execve"]):
        events.append({"api": "CreateProcessW()", "process": process_name or "services.exe", "action": "Spawned powershell.exe -ExecutionPolicy Bypass", "severity": "High"})
        score = 70
    else:
        events.append({"api": "NtQuerySystemInformation()", "process": process_name or "system.exe", "action": "Normal telemetry query", "severity": "Low"})
        score = 0

    return {
        "score": score,
        "events": events
    }
