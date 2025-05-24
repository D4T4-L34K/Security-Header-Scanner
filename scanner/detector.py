from urllib.parse import urlparse

REQUIRED_HEADERS = {
    'HTTPS': {
        '1.1': ["Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options", "Cache-Control"],
        '1.0': ["Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options", "Expires", "X-Frame-Options"]
    },
    'HTTP': {
        '1.1': ["Content-Security-Policy", "X-Content-Type-Options", "Cache-Control", "Set-Cookie"],
        '1.0': ["Content-Security-Policy", "X-Content-Type-Options", "Expires", "X-Frame-Options", "Set-Cookie"]
    }
}

def note(msg, severity="medium"):
    if severity.lower() == "medium":
        return f"Risk: [yellow]Medium[/yellow] - {msg}"
    if severity.lower() == "observation":
        return f"Risk: [blue]Observation[/blue] - {msg}"

def check_csp(csp, internal):
    notes = []
    if not csp:
        if internal:
            msg = "Content-Security-Policy missing"
            notes.append(note(msg, "observation" if internal else "medium"))
    else:
        if "object-src 'none'" not in csp:
            notes.append(note('CSP missing "object-src \'none\'"'))
        elif "script-src 'strict-dynamic'" not in csp:
            notes.append(note('CSP missing optional "script-src \'strict-dynamic\'"', "observation"))
    return notes

def check_strict_transport_security(strict_transport_security):
    notes = []
    if not strict_transport_security:
        notes.append(note("Strict-Transport-Security header missing"))
    else:
        if "max-age" not in strict_transport_security:
            notes.append(note("HSTS missing 'max-age'"))
        if "includeSubDomains" not in strict_transport_security:
            notes.append(note("HSTS missing 'includeSubDomains'", "observation"))
        if "preload" not in strict_transport_security:
            notes.append(note("HSTS missing 'preload'", "observation"))
    return notes

def check_x_content_type_options(value):
    if value.strip().lower() != "nosniff":
        return [note("X-Content-Type-Options is not 'nosniff'")]
    return []

def check_cache_control(value):
    notes = []
    required = ["no-store", "no-cache", "must-revalidate", "max-age"]
    if not value:
        return [note("Cache-Control header missing")]
    for directive in required:
        if directive not in value:
            severity = "medium" if directive in ["no-store", "no-cache"] else "observation"
            notes.append(note(f"Cache-Control missing '{directive}'", severity))
    return notes

def check_set_cookie(values):
    if not values:
        return [note("Set-Cookie header missing")]
    notes = []
    if isinstance(values, str):
        values = [values]

    for cookie in values:
        cookie = cookie.lower()
        if not all(x in cookie for x in ["secure", "httponly", "samesite=strict"]):
            notes.append(note("Set-Cookie missing Secure, HttpOnly, or SameSite=Strict"))
    return notes

def check_expires(value, cache_control):
    if not value and not ("max-age" in cache_control or "s-maxage" in cache_control):
        return [note("Expires header missing and no max-age in Cache-Control")]
    return []

def check_x_frame_options(value):
    if not value:
        return [note("X-Frame-Options header missing")]
    valid = ["deny", "sameorigin"]

    notes = []
    if value.strip().lower() not in valid:
        notes = [note("X-Frame-Options has invalid value")]
    notes.append(note("Use CSP 'frame-ancestors' for better frame control", "observation"))
    return notes

def detect_security_headers(headers, url, version, internal):
    parsed = urlparse(url)
    scheme = parsed.scheme.upper()
    expected_headers = REQUIRED_HEADERS.get(scheme, {}).get(version, {})

    result = {
        "headers": {},
        "notes": []
    }

    norm_headers = {k.lower(): v for k, v in headers.items()}

    for header in expected_headers:
        key = header.lower()
        present = any(h.lower() == key for h in headers)
        result["headers"][header] = present
        if not present:
            result['notes'].append(note(f"Insufficient HTTP Security Header Set (Missing: {header})"))

    # Extended best practices
    result['notes'].extend(check_csp(norm_headers.get("content-security-policy", ""), internal))
    result['notes'].extend(check_strict_transport_security(norm_headers.get("strict-transport-security", "")))
    result['notes'].extend(check_x_content_type_options(norm_headers.get("x-content-type-options", "")))
    result['notes'].extend(check_cache_control(norm_headers.get("cache-control", "")))
    result['notes'].extend(check_set_cookie(headers.get("Set-Cookie", "")))
    result['notes'].extend(check_expires(norm_headers.get("expires", ""), norm_headers.get("cache-control", "")))
    result['notes'].extend(check_x_frame_options(norm_headers.get("x-frame-options", "")))

    return result
