"""
utils/link_detector.py
Regex-based suspicious URL/link detector for call transcripts.
Handles spoken URLs (e.g. "dot com", "slash"), short links, and typosquatting.
"""

import re
from dataclasses import dataclass, field
from typing import List

# ── Patterns ──────────────────────────────────────────────────────────────────

# Standard URLs
_URL_RE = re.compile(
    r'https?://[^\s\)\]\>\"\']+|'          # http(s):// links
    r'www\.[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}[^\s]*',
    re.IGNORECASE,
)

# Spoken URL patterns (common in voice scams)
_SPOKEN_URL_RE = re.compile(
    r'[a-zA-Z0-9\-]+\s*dot\s*com\b|'
    r'[a-zA-Z0-9\-]+\s*dot\s*in\b|'
    r'[a-zA-Z0-9\-]+\s*dot\s*net\b|'
    r'[a-zA-Z0-9\-]+\s*dot\s*org\b|'
    r'[a-zA-Z0-9\-]+\s*dot\s*co\s*dot\s*in\b',
    re.IGNORECASE,
)

# Known URL shorteners
_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "short.io", "rb.gy", "cutt.ly", "is.gd", "tiny.cc",
    "wa.me", "whatsapp.com/dl",
}

# Trusted domains — these are NOT flagged
_TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "instagram.com",
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "paytm.com",
    "npci.org.in", "rbi.org.in", "gov.in", "nic.in",
    "amazon.in", "flipkart.com", "irctc.co.in",
}

# Suspicious TLDs and keywords in domains
_SUSPICIOUS_KEYWORDS = [
    "kyc", "update", "verify", "secure", "login", "account",
    "otp", "reward", "prize", "lucky", "winner", "claim",
    "refund", "cashback", "free", "offer", "limited",
    "sbi-", "hdfc-", "paytm-", "uidai-", "gov-",
    "bank-", "income-tax", "police", "court",
]

_SUSPICIOUS_TLDS = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".click", ".link"]


@dataclass
class SuspiciousLink:
    url: str
    reason: str
    risk: str  # "HIGH" | "MEDIUM" | "LOW"


def _normalise(url: str) -> str:
    """Normalise spoken URLs like 'sbi dot com' → 'sbi.com'"""
    url = re.sub(r'\s*dot\s*', '.', url, flags=re.IGNORECASE)
    url = re.sub(r'\s*slash\s*', '/', url, flags=re.IGNORECASE)
    return url.strip().lower()


def _score_url(url: str) -> SuspiciousLink | None:
    norm = _normalise(url)

    # Strip protocol for domain checks
    domain = re.sub(r'^https?://', '', norm).split('/')[0].split('?')[0]

    # Skip trusted domains
    for trusted in _TRUSTED_DOMAINS:
        if domain == trusted or domain.endswith('.' + trusted):
            return None

    # URL shortener — always suspicious in scam context
    for shortener in _SHORTENERS:
        if shortener in domain:
            return SuspiciousLink(url=url, reason="URL shortener — destination unknown", risk="HIGH")

    # Suspicious TLD
    for tld in _SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return SuspiciousLink(url=url, reason=f"Suspicious TLD ({tld})", risk="HIGH")

    # Suspicious keyword in domain
    for kw in _SUSPICIOUS_KEYWORDS:
        if kw in domain:
            return SuspiciousLink(url=url, reason=f"Suspicious keyword in domain: '{kw}'", risk="HIGH")

    # IP address URL (never legitimate for banking/govt)
    if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
        return SuspiciousLink(url=url, reason="Raw IP address URL — likely phishing", risk="HIGH")

    # Hyphenated brand impersonation (e.g. sbi-kyc.com)
    if re.search(r'(sbi|hdfc|icici|paytm|uidai|rbi|npci|irctc)[-.]', domain):
        return SuspiciousLink(url=url, reason="Possible brand impersonation in domain", risk="HIGH")

    # Generic unknown link — flag as medium
    return SuspiciousLink(url=url, reason="Unknown external link in call", risk="MEDIUM")


def detect_suspicious_links(text: str) -> List[SuspiciousLink]:
    """
    Extract and score all URLs/links from transcript text.
    Returns list of SuspiciousLink objects (empty if none found).
    """
    found: List[SuspiciousLink] = []
    seen = set()

    candidates = _URL_RE.findall(text) + _SPOKEN_URL_RE.findall(text)

    for raw in candidates:
        raw = raw.strip()
        if raw in seen:
            continue
        seen.add(raw)
        result = _score_url(raw)
        if result:
            found.append(result)

    return found
