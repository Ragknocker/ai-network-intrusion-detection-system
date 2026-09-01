import hashlib
import os
import time

def extract_file_metadata(file_path_or_content, filename="unnamed_file"):
    """
    Extracts file metadata including hashes (MD5, SHA1, SHA256), size, extension, and timestamp.
    """
    content = b""
    if isinstance(file_path_or_content, str):
        if os.path.exists(file_path_or_content):
            filename = os.path.basename(file_path_or_content)
            with open(file_path_or_content, "rb") as f:
                content = f.read()
        else:
            content = file_path_or_content.encode("utf-8")
    elif isinstance(file_path_or_content, bytes):
        content = file_path_or_content

    md5_hash = hashlib.md5(content).hexdigest()
    sha1_hash = hashlib.sha1(content).hexdigest()
    sha256_hash = hashlib.sha256(content).hexdigest()

    ext = os.path.splitext(filename)[1].lower()

    return {
        "filename": filename,
        "extension": ext,
        "size_bytes": len(content),
        "md5": md5_hash,
        "sha1": sha1_hash,
        "sha256": sha256_hash,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }
