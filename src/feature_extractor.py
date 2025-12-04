import datetime
import socket
import ssl
from urllib.parse import urlparse

import requests
import tldextract

try:
    import whois  # python-whois package
except ImportError:
    import whois


def _normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def _get_domain(url: str) -> str:
    url = _normalize_url(url)
    parsed = urlparse(url)
    domain = parsed.netloc.split(":")[0]
    return domain.lower()


def _get_domain_age_days(domain: str) -> int:
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return 0

        if hasattr(creation_date, "tzinfo") and creation_date.tzinfo is not None:
            creation_date = creation_date.replace(tzinfo=None)

        age = (datetime.datetime.utcnow() - creation_date).days
        return max(age, 0)
    except Exception:
        return 0


def _has_valid_ssl(domain: str) -> int:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return 1 if cert else 0
    except Exception:
        return 0


def _get_redirect_count(url: str) -> int:
    try:
        url = _normalize_url(url)
        resp = requests.get(url, timeout=5, allow_redirects=True)
        return len(resp.history)
    except Exception:
        return 0


def _count_suspicious_keywords(url: str) -> int:
    suspicious_words = [
        "login", "secure", "signin", "verify", "update",
        "account", "bank", "payment", "confirm", "invoice",
        "paypal", "security", "webscr", "password"
    ]
    text = url.lower()
    return sum(1 for w in suspicious_words if w in text)


def get_osint_details(url: str) -> dict:
    """
    Return human-readable OSINT details for display on UI.
    """
    norm_url = _normalize_url(url)
    parsed = urlparse(norm_url)
    domain = _get_domain(url)
    ext = tldextract.extract(norm_url)

    https_flag = 1 if parsed.scheme == "https" else 0
    domain_age = _get_domain_age_days(domain)
    ssl_valid = _has_valid_ssl(domain)
    redirects = _get_redirect_count(url)
    suspicious_count = _count_suspicious_keywords(url)
    subdomain_count = len(ext.subdomain.split(".")) if ext.subdomain else 0

    return {
        "domain": domain,
        "https": https_flag,
        "domain_age_days": domain_age,
        "ssl_valid": ssl_valid,
        "redirects": redirects,
        "suspicious_keywords": suspicious_count,
        "subdomain_count": subdomain_count,
    }


def extract_features(url: str):
    """
    Converts a URL string into a 30-feature numeric vector.
    Uses lexical + OSINT-based features, then pads to length 30.
    """
    norm_url = _normalize_url(url)
    parsed = urlparse(norm_url)
    domain = _get_domain(url)
    ext = tldextract.extract(norm_url)

    # Get OSINT values once
    osint = get_osint_details(url)

    features = []

    # -------- Basic lexical features --------
    features.append(len(norm_url))                         # 1 URL length
    features.append(norm_url.count("."))                   # 2 dots
    features.append(1 if "@" in norm_url else 0)           # 3 @
    features.append(norm_url.count("//"))                  # 4 //
    features.append(norm_url.count("-"))                   # 5 -
    features.append(norm_url.count("?"))                   # 6 ?
    features.append(norm_url.count("="))                   # 7 =
    features.append(sum(c.isdigit() for c in norm_url))    # 8 digits
    features.append(sum(c.isalpha() for c in norm_url))    # 9 letters
    features.append(len(ext.suffix))                       # 10 TLD length
    features.append(len(domain))                           # 11 domain length
    features.append(len(parsed.path))                      # 12 path length
    features.append(osint["https"])                        # 13 HTTPS flag

    # -------- OSINT-based features --------
    features.append(osint["domain_age_days"])              # 14 domain age
    features.append(osint["ssl_valid"])                    # 15 SSL valid
    features.append(osint["redirects"])                    # 16 redirects
    features.append(osint["suspicious_keywords"])          # 17 suspicious kw
    features.append(osint["subdomain_count"])              # 18 subdomains

    # Pad to 30
    while len(features) < 30:
        features.append(0)

    return features[:30]
