from __future__ import annotations

import hashlib
import ipaddress
import re
from urllib.parse import urlparse


def detect_indicator(value: str) -> str:
    value = value.strip()
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if re.fullmatch(r"(?i)[0-9a-f]{32}", value):
        return "md5"
    if re.fullmatch(r"(?i)[0-9a-f]{40}", value):
        return "sha1"
    if re.fullmatch(r"(?i)[0-9a-f]{64}", value):
        return "sha256"
    if value.lower().startswith(("http://", "https://")):
        return "url"
    return "domain"


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError("URL must start with http:// or https://")
    parsed = urlparse(url)
    if not parsed.hostname:
        raise ValueError("Invalid URL: missing hostname.")
    if any(ord(c) < 32 for c in url):
        raise ValueError("URL contains control characters.")
    return url


def normalize_domain(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", value):
        raise ValueError("Invalid domain name.")
    return value


def validate_hash(value: str) -> str:
    value = value.strip().lower()
    if len(value) not in {32, 40, 64} or not re.fullmatch(r"[0-9a-f]+", value):
        raise ValueError("Enter a valid MD5, SHA1, or SHA256 hash.")
    return value


def document_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
