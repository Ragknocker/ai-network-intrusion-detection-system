import re
import time
from urllib.parse import urlparse, unquote, idna

# In-memory deduplication cache: url_hash -> timestamp
_DEDUPLICATION_WINDOW_SEC = 300
_seen_url_timestamps = {}

def normalize_url(raw_url):
    """
    Preprocesses and normalizes URLs:
    - Lowercase scheme and hostname
    - Strip default ports (:80, :443)
    - Percent-decode path & query parameters
    - IDN / Punycode homoglyph resolution (xn-- -> unicode)
    - Fragment stripping (#... removed while retaining query strings)
    - Returns normalized URL string and metadata flags
    """
    url = (raw_url or "").strip() if isinstance(raw_url, str) else ""
    if not url:
        return "", {"is_punycode": False, "percent_decoded": False, "fragment_stripped": False}

    fragment_stripped = False
    if "#" in url:
        url = url.split("#")[0]
        fragment_stripped = True

    percent_decoded = False
    if "%" in url:
        decoded = unquote(url)
        if decoded != url:
            percent_decoded = True
            url = decoded

    if not (url.lower().startswith("http://") or url.lower().startswith("https://") or url.lower().startswith("ftp://")):
        formatted = "http://" + url
    else:
        formatted = url

    try:
        parsed = urlparse(formatted)
    except Exception:
        return url.lower(), {"is_punycode": False, "percent_decoded": percent_decoded, "fragment_stripped": fragment_stripped}

    scheme = (parsed.scheme or "http").lower()
    netloc = (parsed.netloc or "").lower()

    # Strip default ports
    if scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]

    # Resolve IDN / Punycode homoglyphs
    is_punycode = "xn--" in netloc
    hostname = parsed.hostname or netloc
    if is_punycode and hostname:
        try:
            unicode_host = hostname.encode("ascii").decode("idna")
            netloc = netloc.replace(hostname, unicode_host)
        except Exception:
            pass

    normalized = f"{scheme}://{netloc}{parsed.path}"
    if parsed.query:
        normalized += f"?{parsed.query}"

    return normalized, {
        "is_punycode": is_punycode,
        "percent_decoded": percent_decoded,
        "fragment_stripped": fragment_stripped,
        "scheme": scheme,
        "hostname": hostname
    }

def is_duplicate_url(normalized_url):
    """
    Deduplicates near-identical URLs within a 5-minute time window.
    """
    now = time.time()
    # Expire old entries
    expired = [u for u, ts in _seen_url_timestamps.items() if now - ts > _DEDUPLICATION_WINDOW_SEC]
    for u in expired:
        del _seen_url_timestamps[u]

    if normalized_url in _seen_url_timestamps:
        return True

    _seen_url_timestamps[normalized_url] = now
    return False

def capture_and_parse_url(raw_url, source_protocol="HTTP/1.1", src_ip="192.168.1.105", dst_ip="104.21.32.8"):
    """
    Parses URL components (scheme, hostname, port, path, query parameters)
    and constructs a normalized security event.
    """
    url = (raw_url or "").strip() if isinstance(raw_url, str) else ""
    normalized_url, norm_meta = normalize_url(url)

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or "unknown"
    path = parsed.path
    query = parsed.query

    is_dedup = is_duplicate_url(normalized_url)

    return {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "raw_url": raw_url,
        "normalized_url": normalized_url,
        "scheme": parsed.scheme or "http",
        "hostname": hostname,
        "port": parsed.port or (443 if parsed.scheme == "https" else 80),
        "path": path,
        "query": query,
        "params_count": len(query.split("&")) if query else 0,
        "source_protocol": source_protocol,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "is_duplicate": is_dedup,
        "normalization_metadata": norm_meta
    }

