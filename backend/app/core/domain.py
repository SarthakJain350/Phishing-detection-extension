"""Offline-safe domain normalization and Public Suffix List parsing.

IMPORTANT PRIVACY & SECURITY GUARDRAILS:
1. Operates strictly offline by initializing tldextract with suffix_list_urls=(),
   forcing the use of the package's bundled Public Suffix List snapshot.
2. Extracts and returns only normalized domain/hostname identifiers (e.g. 'login.example.com').
3. Strips paths, query parameters, auth credentials, fragments, and ports before
   storage or persistence to enforce privacy boundaries.
"""

from __future__ import annotations

import ipaddress
import re
import urllib.parse
from dataclasses import dataclass

import tldextract

# Explicitly disable remote fetching at runtime to guarantee deterministic, offline execution.
_OFFLINE_TLD_EXTRACTOR = tldextract.TLDExtract(
    suffix_list_urls=(),
    cache_dir=False,
    fallback_to_snapshot=True,
)

# Regex to check valid hostname characters (alphanumeric, hyphens, dots)
_HOSTNAME_CHARS_REGEX = re.compile(r"^[a-z0-9\.\-_:\[\]]+$")


@dataclass(frozen=True)
class DomainInfo:
    """Structured breakdown of an extracted and normalized domain target."""
    raw_input: str
    target_reference: str  # Lowercase normalized hostname (stored in DB)
    registered_domain: str  # e.g. 'paypal.co.uk'
    subdomain: str  # e.g. 'login.security'
    suffix: str  # e.g. 'co.uk'
    is_ip: bool  # True if the target is an IPv4 or IPv6 address
    is_ipv4: bool
    is_ipv6: bool


def _is_ip_address(host: str) -> tuple[bool, bool, bool]:
    """Check if the given host string is an IPv4 or IPv6 address.

    Returns:
        (is_ip, is_ipv4, is_ipv6)
    """
    cleaned = host.strip("[]")
    try:
        ip = ipaddress.ip_address(cleaned)
        if isinstance(ip, ipaddress.IPv4Address):
            return True, True, False
        if isinstance(ip, ipaddress.IPv6Address):
            return True, False, True
    except ValueError:
        pass
    return False, False, False


def clean_url_or_hostname(value: str) -> str:
    """Extract and isolate the raw hostname from a URL, email domain, or hostname string.

    Removes schemes, credentials, ports, paths, queries, fragments, trailing dots,
    and whitespace. Validates schemes, allowing only http and https.
    """
    if not value or not isinstance(value, str):
        raise ValueError("URL or hostname input must be a non-empty string.")

    cleaned = value.strip()
    if not cleaned:
        raise ValueError("URL or hostname input cannot be empty or whitespace.")

    # Check for known non-http(s) schemes (e.g. ftp://, javascript:, data:, mailto:)
    if ":" in cleaned:
        potential_scheme = cleaned.split(":", 1)[0].lower()
        if potential_scheme in {"ftp", "javascript", "data", "mailto", "file", "ws", "wss", "ssh", "telnet"}:
            raise ValueError(f"Unsupported scheme '{potential_scheme}'. Only http and https are permitted.")

    # Handle URLs with or without scheme (case-insensitive)
    lower_cleaned = cleaned.lower()
    if lower_cleaned.startswith(("http://", "https://")):
        parsed = urllib.parse.urlsplit(cleaned)
    elif "://" in cleaned:
        scheme = cleaned.split("://", 1)[0].lower()
        if scheme not in {"http", "https"}:
            raise ValueError(f"Unsupported URL scheme '{scheme}'. Only http and https are permitted.")
        parsed = urllib.parse.urlsplit(cleaned)
    else:
        parsed = urllib.parse.urlsplit(f"http://{cleaned}")

    host = parsed.hostname
    if not host:
        raise ValueError(f"Could not extract a valid host from '{value}'.")

    # Lowercase and strip trailing dot
    host = host.lower().rstrip(".")

    if not host or host in {"http", "https"}:
        raise ValueError(f"Invalid host extracted from '{value}'.")

    # Handle Punycode conversion for IDN domains
    try:
        host = host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        # If IDNA encoding fails, keep lowercase cleaned host
        pass

    # Basic hostname character check
    if not _HOSTNAME_CHARS_REGEX.match(host):
        raise ValueError(f"Host '{host}' contains invalid characters.")

    return host


def extract_domain_info(url_or_domain: str) -> DomainInfo:
    """Extract structured domain information using offline bundled Public Suffix List snapshot.

    Args:
        url_or_domain: A URL string (e.g. 'https://sub.domain.co.uk:8080/path')
                       or raw hostname (e.g. 'sub.domain.co.uk').

    Returns:
        DomainInfo with target_reference, registered_domain, subdomain, suffix, and IP flags.

    Raises:
        ValueError: If input is invalid, empty, or unparseable.
    """
    normalized_host = clean_url_or_hostname(url_or_domain)

    is_ip, is_ipv4, is_ipv6 = _is_ip_address(normalized_host)
    if is_ip:
        return DomainInfo(
            raw_input=url_or_domain,
            target_reference=normalized_host,
            registered_domain=normalized_host,
            subdomain="",
            suffix="",
            is_ip=True,
            is_ipv4=is_ipv4,
            is_ipv6=is_ipv6,
        )

    # Use offline tldextract to separate subdomains from multi-level public suffixes
    extracted = _OFFLINE_TLD_EXTRACTOR(normalized_host)

    subdomain = extracted.subdomain.lower() if extracted.subdomain else ""
    domain = extracted.domain.lower() if extracted.domain else ""
    suffix = extracted.suffix.lower() if extracted.suffix else ""

    if domain and suffix:
        registered_domain = f"{domain}.{suffix}"
    elif domain:
        registered_domain = domain
    else:
        registered_domain = normalized_host

    # Target reference is the full normalized hostname (stored in DB)
    return DomainInfo(
        raw_input=url_or_domain,
        target_reference=normalized_host,
        registered_domain=registered_domain,
        subdomain=subdomain,
        suffix=suffix,
        is_ip=False,
        is_ipv4=False,
        is_ipv6=False,
    )


def normalize_target_reference(url_or_domain: str) -> str:
    """Convenience helper to extract and return only the normalized target_reference string.

    This is the string persisted in `scans.target_reference`.
    """
    return extract_domain_info(url_or_domain).target_reference
