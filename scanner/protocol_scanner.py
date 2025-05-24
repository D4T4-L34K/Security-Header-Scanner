import requests
from urllib.parse import urlparse, urlunparse
from scanner.detector import detect_security_headers

SCHEMES = ["http", "https"]
VERSIONS = ["1.1", "1.0"]
TIMEOUT = 5

def is_scheme_supported(url, scheme):
    parsed = urlparse(url)
    test_url = urlunparse((scheme, parsed.netloc, parsed.path, "", "", ""))
    try:
        response = requests.get(test_url, allow_redirects=False, timeout=TIMEOUT)
        if response.status_code == 200:
            return True
        return False
    except requests.RequestException:
        return False

def scan_with_version(url, version, internal):
    try:
        session = requests.Session()
        headers = {"Connection": "close"} # simulate HTTP/1.0
        response = session.get(url, headers=headers, timeout=TIMEOUT)
        detected = detect_security_headers(response.headers, url, version, internal)
        return detected
    except requests.RequestException:
        return None

def scan_all_protocols(url, internal):
    results: dict[str, dict[str, dict[str, bool] | None]] = {
        "HTTPS": {"1.1": None, "1.0": None},
        "HTTP": {"1.1": None, "1.0": None}
    }

    parsed = urlparse(url)
    host = parsed.netloc or parsed.path

    for scheme in SCHEMES:
        if not is_scheme_supported(url, scheme):
            continue

        for version in VERSIONS:
            scan_url = urlunparse((scheme, host, '', '', '', ''))
            result = scan_with_version(scan_url, version, internal)
            results[scheme.upper()][version] = result

    return results
