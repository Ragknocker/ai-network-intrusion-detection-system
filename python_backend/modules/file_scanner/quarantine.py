import os
import json
import time

QUARANTINE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "quarantine")
os.makedirs(QUARANTINE_DIR, exist_ok=True)

def quarantine_file_backend(filename, file_content, threat_score, sha256):
    """
    Moves dangerous file into quarantine vault storage and generates JSON metadata audit.
    """
    file_id = f"QUAR-{int(time.time())}"
    quarantine_path = os.path.join(QUARANTINE_DIR, f"{file_id}_{sha256[:10]}.bin")

    if isinstance(file_content, str):
        data = file_content.encode("utf-8")
    else:
        data = file_content

    with open(quarantine_path, "wb") as f:
        f.write(data)

    metadata = {
        "id": file_id,
        "filename": filename,
        "sha256": sha256,
        "threat_score": threat_score,
        "quarantined_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "quarantine_file_path": quarantine_path
    }

    meta_path = os.path.join(QUARANTINE_DIR, f"{file_id}_{sha256[:10]}.json")
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)

    return metadata

def list_quarantined_files():
    items = []
    if not os.path.exists(QUARANTINE_DIR):
        return items
    for fname in os.listdir(QUARANTINE_DIR):
        if fname.endswith(".json"):
            p = os.path.join(QUARANTINE_DIR, fname)
            try:
                with open(p, "r") as f:
                    items.append(json.load(f))
            except Exception:
                pass
    return items
