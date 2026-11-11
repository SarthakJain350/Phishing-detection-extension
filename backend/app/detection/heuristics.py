"""Deterministic URL and text heuristics engine for phishing detection.

DESIGN PRINCIPLES:
- 100% offline: uses only Python standard library and the existing offline
  domain.py module (no network calls at evaluation time).
- Returns typed EvidenceItem objects with stable rule identifiers, human-
  readable explanations, and severity classifications.
- Stateless and side-effect-free: safe to call from tests, workers, or
  async contexts without any external dependencies.

RULE IDENTIFIERS (stable, machine-readable, suitable for serialization):
  ip_hostname              - Raw IP address used instead of a domain name.
  punycode_homoglyph       - Punycode prefix (xn--) indicating potential IDN
                             homoglyph spoofing.
  misleading_subdomain     - High-value brand keyword in subdomain while the
                             registered domain belongs to a different entity.
  url_excessive_length     - URL exceeds 100 characters (structural anomaly).
  at_symbol_redirect       - '@' in URL authority, a classic credential-hiding
                             and redirect-confusion vector.
  excessive_hyphens        - More than 2 hyphens in the hostname labels.
  deep_subdomain_nesting   - 4+ domain label levels (deep nesting is rare in
                             legitimate sites and common in phishing kits).
  urgency_language         - Urgency / threat language typical of social-
                             engineering pressure tactics.
  credential_harvesting_language - Explicit credential-solicitation language
                             rarely used by legitimate services in page text.
  path_suspicious_script_endpoint - Standalone script endpoint frequently
                             deployed in phishing kits (e.g. captcha.php, webscr.php).
"""

from __future__ import annotations

import ipaddress
import re
import urllib.parse

from backend.app.core.domain import extract_domain_info
from backend.app.schemas.scan import EvidenceItem

# ---------------------------------------------------------------------------
# Brand keyword list for misleading-subdomain detection.
# These are high-value brands routinely impersonated in phishing kits.
# The set intentionally stays small and high-precision to minimise false
# positives; extension is a deliberate product decision, not a quick fix.
# ---------------------------------------------------------------------------
_IMPERSONATED_BRANDS: frozenset[str] = frozenset({
    "paypal",
    "apple",
    "google",
    "microsoft",
    "chase",
    "wellsfargo",
    "amazon",
    "netflix",
    "bankofamerica",
    "facebook",
    "instagram",
    "twitter",
    "linkedin",
    "dropbox",
    "icloud",
    "yahoo",
    "citibank",
    "barclays",
    "hsbc",
})

# ---------------------------------------------------------------------------
# Urgency / social-engineering language patterns.
# Patterns are case-insensitive; match on full phrase, not substring fragments.
# ---------------------------------------------------------------------------
_URGENCY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"account\s+(?:has\s+been\s+)?(?:suspended|locked|compromised|disabled)", re.IGNORECASE),
    re.compile(r"verify\s+(?:your\s+account\s+)?within\s+\d+\s+hours?", re.IGNORECASE),
    re.compile(r"immediate\s+action\s+(?:is\s+)?required", re.IGNORECASE),
    re.compile(r"click\s+(?:here\s+)?(?:now|immediately|urgently)\s+to\s+(?:avoid|prevent|secure)", re.IGNORECASE),
    re.compile(r"unusual\s+(?:sign[- ]in|login|activity|access)\s+(?:attempt|detected|noticed)", re.IGNORECASE),
    re.compile(r"your\s+(?:account\s+)?(?:will\s+be\s+)?(?:suspended|deleted|terminated|closed)\s+(?:in|within|after)", re.IGNORECASE),
    re.compile(r"confirm\s+your\s+(?:identity|account|information|details)\s+(?:to\s+avoid|immediately|now|or)", re.IGNORECASE),
    re.compile(r"limited\s+time\s+(?:offer|action|window)", re.IGNORECASE),
    re.compile(r"update\s+(?:your\s+)?(?:payment|billing|account)\s+(?:information|details|now)", re.IGNORECASE),
]

_CREDENTIAL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:verify|enter|confirm|provide)\s+(?:your\s+)?password", re.IGNORECASE),
    re.compile(r"(?:enter|confirm|provide|input)\s+(?:your\s+)?(?:social\s+security|SSN)\s+(?:number)?", re.IGNORECASE),
    re.compile(r"(?:enter|provide|confirm)\s+(?:your\s+)?(?:PIN|one[- ]time\s+(?:password|code)|OTP)", re.IGNORECASE),
    re.compile(r"(?:enter|provide|verify)\s+(?:your\s+)?(?:full\s+)?(?:credit|debit)\s+card\s+(?:number|details)", re.IGNORECASE),
    re.compile(r"(?:enter|confirm|provide)\s+(?:your\s+)?date\s+of\s+birth", re.IGNORECASE),
    re.compile(r"(?:enter|confirm|provide)\s+(?:your\s+)?(?:bank\s+)?(?:routing|account)\s+number", re.IGNORECASE),
    re.compile(r"re[- ]?enter\s+(?:your\s+)?(?:password|PIN|credentials)", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# Individual detector functions
# ---------------------------------------------------------------------------

def detect_ip_hostname(url: str) -> EvidenceItem | None:
    """Return an EvidenceItem if the URL's host is a raw IPv4 or IPv6 address.

    A legitimate website almost never uses a raw IP address as its hostname;
    phishing kits often do to avoid domain registration and detection.

    Args:
        url: The full URL submitted for scanning.

    Returns:
        EvidenceItem if the host is a raw IP; None for named hostnames.
    """
    try:
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname or ""
        # Strip IPv6 brackets
        host_clean = host.strip("[]")
        ipaddress.ip_address(host_clean)
        # Reached here → it is a valid IP
        return EvidenceItem(
            type="ip_hostname",
            source="heuristics",
            severity="high",
            explanation=(
                f"The URL uses a raw IP address ({host_clean!r}) as its hostname. "
                "Legitimate websites use registered domain names; raw IP addresses "
                "are a strong phishing indicator."
            ),
        )
    except ValueError:
        return None


def detect_punycode_and_lookalike(hostname: str) -> EvidenceItem | None:
    """Return an EvidenceItem if any hostname label begins with the Punycode prefix 'xn--'.

    Attackers register internationalized domain names (IDNs) whose Unicode
    rendering closely resembles high-value brand names (e.g. 'pаypal.com'
    with a Cyrillic 'а'). The Punycode encoding of such domains starts with
    'xn--'.

    Note: 'xn--' alone does not prove malice (many legitimate IDNs exist), but
    it is a meaningful elevated-risk signal worth surfacing explicitly.

    Args:
        hostname: Normalized lowercase hostname (not a full URL).

    Returns:
        EvidenceItem if any label is Punycode-encoded; None otherwise.
    """
    labels = hostname.lower().split(".")
    punycode_labels = [label for label in labels if label.startswith("xn--")]
    if not punycode_labels:
        return None

    return EvidenceItem(
        type="punycode_homoglyph",
        source="heuristics",
        severity="high",
        explanation=(
            f"The hostname contains Punycode-encoded labels ({', '.join(punycode_labels)}). "
            "Attackers use internationalized domain names with visually similar characters "
            "('homoglyphs') to impersonate trusted brands. Treat this URL with extreme caution."
        ),
    )


def detect_misleading_subdomains(url: str) -> list[EvidenceItem]:
    """Return EvidenceItems if a trusted-brand keyword appears in the subdomain
    while the registered domain is NOT that brand.

    Example positives:
        paypal.com.evil-host.net  → subdomain contains 'paypal.com'; registered domain is evil-host.net
        google.account-secure.xyz → subdomain contains 'google'; registered domain is account-secure.xyz

    Example negatives (no evidence produced):
        checkout.paypal.com        → registered domain IS paypal.com — not misleading
        login.google.com           → registered domain IS google.com — not misleading
        en.wikipedia.org           → no brand keyword in subdomain at all

    Args:
        url: The full URL submitted for scanning.

    Returns:
        List of EvidenceItems (may be empty if no misleading subdomains detected).
    """
    try:
        info = extract_domain_info(url)
    except ValueError:
        return []

    if info.is_ip or not info.subdomain:
        return []

    # Split registered_domain into its base domain label for matching
    # e.g. 'paypal.co.uk' → base_domain_label = 'paypal'
    base_domain_label = info.registered_domain.split(".")[0].lower()
    subdomain_lower = info.subdomain.lower()

    # Tokenize subdomain labels using dots and hyphens to avoid substring false positives
    # (e.g. 'purchase' must not match 'chase', 'pineapple' must not match 'apple',
    # and single-letter matches like 'x' are eliminated).
    subdomain_tokens = set(filter(None, re.split(r"[\.-]+", subdomain_lower)))

    evidence: list[EvidenceItem] = []
    for brand in _IMPERSONATED_BRANDS:
        # Brand must match a complete token in the subdomain AND registered domain must NOT be that brand
        if brand in subdomain_tokens and base_domain_label != brand:
            evidence.append(
                EvidenceItem(
                    type="misleading_subdomain",
                    source="heuristics",
                    severity="high",
                    explanation=(
                        f"The subdomain contains the brand keyword '{brand}' "
                        f"(full hostname: {info.target_reference!r}), but the registered domain "
                        f"is '{info.registered_domain}', which is not affiliated with '{brand}'. "
                        "This is a classic phishing technique designed to deceive users who read "
                        "only the beginning of a URL."
                    ),
                )
            )
            # Report each distinct impersonated brand once
            break  # Most URLs impersonate a single brand; break after first hit to avoid noise

    return evidence


def detect_url_structure_anomalies(url: str) -> list[EvidenceItem]:
    """Return EvidenceItems for structural URL anomalies associated with phishing.

    Checks performed:
    1. URL length > 100 characters (url_excessive_length, medium).
    2. '@' symbol in URL authority component (at_symbol_redirect, high).
    3. More than 2 hyphens in the hostname, ignoring 'xn--' punycode prefix (excessive_hyphens, low).
    4. 3 or more subdomain levels / deep subdomain nesting, excluding public suffixes
       (deep_subdomain_nesting, medium).

    Args:
        url: The full URL submitted for scanning.

    Returns:
        List of EvidenceItems (may be empty).
    """
    evidence: list[EvidenceItem] = []

    # 1. Excessive URL length
    # Severity: low.  URL length is a weak, easily mimicked structural signal that
    # frequently fires on legitimate transactional, tracking, and unsubscribe URLs
    # (e.g. OAuth tokens, UTM parameters, unsubscribe UUIDs).  It is preserved as a
    # supporting indicator but must not independently drive a high risk score.
    if len(url) > 100:
        evidence.append(
            EvidenceItem(
                type="url_excessive_length",
                source="heuristics",
                severity="low",
                explanation=(
                    f"The URL is {len(url)} characters long, which is unusually long. "
                    "Phishing URLs often pad legitimate-looking path segments or query strings "
                    "to obscure the true destination and confuse users."
                ),
            )
        )

    # 2. '@' symbol in URL (credential-hiding / redirect confusion vector)
    # RFC 3986 allows userinfo@host; browsers display only the part after '@' as the host,
    # so 'https://trusted-bank.com@evil.com/' navigates to evil.com.
    try:
        parsed = urllib.parse.urlsplit(url)
        # netloc includes userinfo@host; check for '@' there
        if "@" in (parsed.netloc or ""):
            evidence.append(
                EvidenceItem(
                    type="at_symbol_redirect",
                    source="heuristics",
                    severity="high",
                    explanation=(
                        "The URL contains an '@' symbol in its authority component. "
                        "Browsers interpret the part after '@' as the real host, allowing "
                        "attackers to place a trusted domain name before '@' to deceive users "
                        "(e.g. 'https://trusted-bank.com@evil.com/phish')."
                    ),
                )
            )
        hostname = parsed.hostname or ""
    except Exception:  # noqa: BLE001
        hostname = ""

    if hostname:
        # Strip any IPv6 brackets for hyphen checks
        host_clean = hostname.strip("[]")

        # 3. Excessive hyphens in hostname labels (> 2 total across all labels)
        # Strip the 'xn--' ACE prefix from Punycode labels so encoding syntax
        # does not independently inflate the deceptive-hyphen count.
        labels = host_clean.split(".")
        cleaned_labels = [l[4:] if l.lower().startswith("xn--") else l for l in labels]
        total_hyphens = sum(l.count("-") for l in cleaned_labels)
        if total_hyphens > 2:
            evidence.append(
                EvidenceItem(
                    type="excessive_hyphens",
                    source="heuristics",
                    severity="low",
                    explanation=(
                        f"The hostname contains {total_hyphens} hyphens. "
                        "Phishing domains frequently embed hyphens to assemble fake-looking "
                        "'secure' or 'login' hostnames (e.g. 'secure-login-paypal-verify.com'). "
                        "This is a weak signal and should be considered alongside other findings."
                    ),
                )
            )

    # 4. Deep subdomain nesting: calculate actual subdomain depth from domain parsing.
    # Exclude public suffix and registered domain labels.
    # Threshold: >= 3 subdomain levels (e.g. 'a.b.c.example.com') indicates deep nesting.
    # Severity: low.  Deeply nested subdomains are a weak indicator on their own because
    # many legitimate services use service.region.env.corp.com-style hostnames.  This
    # signal is preserved as a supporting indicator and gains weight when combined with
    # independent high-confidence signals (misleading_subdomain, ip_hostname, punycode).
    try:
        info = extract_domain_info(url)
        if not info.is_ip and info.subdomain:
            subdomain_labels = [l for l in info.subdomain.split(".") if l]
            if len(subdomain_labels) >= 3:
                evidence.append(
                    EvidenceItem(
                        type="deep_subdomain_nesting",
                        source="heuristics",
                        severity="low",
                        explanation=(
                            f"The hostname has {len(subdomain_labels)} subdomain levels "
                            f"(subdomain: {info.subdomain!r}). Deep subdomain nesting is uncommon on "
                            "legitimate websites and is often used by phishing kits to pad URLs "
                            "with plausible-looking segments."
                        ),
                    )
                )
    except ValueError:
        pass

    return evidence


# ---------------------------------------------------------------------------
# Suspicious script endpoint detector
# ---------------------------------------------------------------------------

_SUSPICIOUS_SCRIPT_ENDPOINT_RE = re.compile(
    r"(?:^|/)(?P<endpoint>captcha|webscr|checkpoint)\.php$",
    re.IGNORECASE,
)


def detect_suspicious_script_endpoint(url: str) -> EvidenceItem | None:
    """Return an EvidenceItem if the URL's path ends in a known phishing kit script.

    Target endpoints (strictly case-insensitive, complete path-segment matches):
    - captcha.php: Phishing kit anti-bot challenge and reverse-proxy cloaking gate.
    - webscr.php: Classic credential-harvesting endpoint mimicking payment/auth workflows.
    - checkpoint.php: Account challenge/verification harvester.

    Explicitly excluded due to legitimate web usage:
    - submit.php
    - session.php

    Args:
        url: The full URL submitted for scanning.

    Returns:
        EvidenceItem if path targets a suspicious script endpoint; None otherwise.
    """
    try:
        parsed = urllib.parse.urlsplit(url)
        raw_path = parsed.path or ""
        # Percent-decode the path exactly once using unquote
        decoded_path = urllib.parse.unquote(raw_path)
        # Strip trailing slashes to evaluate the terminal file segment
        clean_path = decoded_path.rstrip("/")
        if not clean_path:
            return None

        # Extract the terminal path segment
        filename = clean_path.split("/")[-1]

        match = _SUSPICIOUS_SCRIPT_ENDPOINT_RE.match(filename)
        if match:
            endpoint = match.group("endpoint").lower() + ".php"
            return EvidenceItem(
                type="path_suspicious_script_endpoint",
                source="heuristics",
                severity="medium",
                explanation=(
                    f"The URL targets a standalone script endpoint ({endpoint!r}) frequently "
                    "deployed in phishing kits for credential harvesting, bot cloaking, or "
                    "payment interface spoofing."
                ),
            )
        return None
    except Exception:  # noqa: BLE001
        return None


def detect_urgency_and_credential_language(text: str | None) -> list[EvidenceItem]:
    """Return EvidenceItems for urgency or credential-harvesting language found in page text.

    Two sub-checks:
    - urgency_language:               Phrases creating artificial time pressure or threat.
    - credential_harvesting_language: Explicit requests for passwords, PINs, SSNs, or
                                      financial credentials outside of a normal authenticated form.

    Args:
        text: Visible page text, email subject, or email body excerpt (may be None).

    Returns:
        List of EvidenceItems (may be empty if no text or no matches).
    """
    if not text or not text.strip():
        return []

    evidence: list[EvidenceItem] = []

    # Urgency check — report first match only to avoid flooding
    for pattern in _URGENCY_PATTERNS:
        match = pattern.search(text)
        if match:
            evidence.append(
                EvidenceItem(
                    type="urgency_language",
                    source="heuristics",
                    severity="medium",
                    explanation=(
                        "The text contains urgency or coercive language typical of "
                        "social-engineering tactics designed to pressure immediate action."
                    ),
                )
            )
            break  # One urgency finding is sufficient; additional matches are noise

    # Credential harvesting check — report first match only
    for pattern in _CREDENTIAL_PATTERNS:
        match = pattern.search(text)
        if match:
            evidence.append(
                EvidenceItem(
                    type="credential_harvesting_language",
                    source="heuristics",
                    severity="medium",
                    explanation=(
                        "The text explicitly solicits sensitive credentials (such as "
                        "passwords, payment details, or personal identity information) "
                        "outside of a standard secure workflow."
                    ),
                )
            )
            break  # One credential finding is sufficient

    return evidence


# ---------------------------------------------------------------------------
# Engine class
# ---------------------------------------------------------------------------

class DeterministicHeuristicsEngine:
    """Stateless engine running all deterministic URL and text heuristic checks.

    Usage:
        engine = DeterministicHeuristicsEngine()
        evidence = engine.analyze_website(
            url="https://paypal.com.secure-login.xyz/verify",
            target_reference="paypal.com.secure-login.xyz",
        )

    The engine makes zero network calls during analysis. It relies exclusively
    on:
    - Python's standard library (ipaddress, re, urllib.parse).
    - The offline domain normalization module (backend.app.core.domain).
    """

    def analyze_website(
        self,
        *,
        url: str,
        target_reference: str,
        page_title: str | None = None,
        visible_text: str | None = None,
    ) -> list[EvidenceItem]:
        """Run all heuristic checks on a website scan target.

        Args:
            url:              The full URL as submitted (used for structural checks).
            target_reference: Normalized hostname stored in the database (privacy-safe).
            page_title:       Optional visible page title (included in text analysis).
            visible_text:     Optional bounded visible text excerpt.

        Returns:
            List of EvidenceItem objects (may be empty for clean URLs).
        """
        evidence: list[EvidenceItem] = []

        # --- Structural URL checks ---
        ip_evidence = detect_ip_hostname(url)
        if ip_evidence:
            evidence.append(ip_evidence)

        punycode_evidence = detect_punycode_and_lookalike(target_reference)
        if punycode_evidence:
            evidence.append(punycode_evidence)

        evidence.extend(detect_misleading_subdomains(url))
        evidence.extend(detect_url_structure_anomalies(url))

        script_evidence = detect_suspicious_script_endpoint(url)
        if script_evidence:
            evidence.append(script_evidence)

        # --- Text / content checks ---
        # Combine page title and visible text; both are optional
        combined_text_parts: list[str] = []
        if page_title:
            combined_text_parts.append(page_title)
        if visible_text:
            combined_text_parts.append(visible_text)
        combined_text = " ".join(combined_text_parts) if combined_text_parts else None

        evidence.extend(detect_urgency_and_credential_language(combined_text))

        return evidence

    def analyze_email(
        self,
        *,
        sender: str | None = None,
        subject: str | None = None,
        body_text: str | None = None,
        links: list[str] | None = None,
    ) -> list[EvidenceItem]:
        """Run all heuristic checks on an email scan target.

        Args:
            sender:    Sender string or email address (not currently analysed for URL
                       structure — that would require extracting the domain).
            subject:   Email subject line.
            body_text: Bounded plain-text excerpt of the email body.
            links:     Capped list of URLs extracted from the email body (≤ 10).

        Returns:
            List of EvidenceItem objects (may be empty for clean emails).
        """
        evidence: list[EvidenceItem] = []

        # Collect raw link-level evidence across all provided links
        raw_link_evidence: list[EvidenceItem] = []
        for link in (links or []):
            if not link:
                continue
            ip_evidence = detect_ip_hostname(link)
            if ip_evidence:
                raw_link_evidence.append(ip_evidence)

            try:
                parsed = urllib.parse.urlsplit(link)
                hostname = (parsed.hostname or "").strip("[]")
                if hostname:
                    punycode_evidence = detect_punycode_and_lookalike(hostname)
                    if punycode_evidence:
                        raw_link_evidence.append(punycode_evidence)
            except Exception:  # noqa: BLE001
                pass

            raw_link_evidence.extend(detect_misleading_subdomains(link))
            raw_link_evidence.extend(detect_url_structure_anomalies(link))

        # Consolidate repeating link-level findings so multiple links triggering the
        # same heuristic rule code do not generate redundant evidence items.
        # Preserve useful context (such as number of affected URLs) without storing
        # raw URLs or sensitive query parameters.
        length_items = [i for i in raw_link_evidence if i.type == "url_excessive_length"]
        nesting_items = [i for i in raw_link_evidence if i.type == "deep_subdomain_nesting"]
        hyphen_items = [i for i in raw_link_evidence if i.type == "excessive_hyphens"]
        at_items = [i for i in raw_link_evidence if i.type == "at_symbol_redirect"]

        # 1. Excessive URL length
        if len(length_items) == 1:
            evidence.append(length_items[0])
        elif len(length_items) > 1:
            long_lengths = [len(l) for l in (links or []) if l and len(l) > 100]
            max_len = max(long_lengths) if long_lengths else 100
            evidence.append(
                EvidenceItem(
                    type="url_excessive_length",
                    source="heuristics",
                    severity="low",
                    explanation=(
                        f"{len(length_items)} links in this email exceed 100 characters in length "
                        f"(longest is {max_len} characters). "
                        "Phishing URLs often pad legitimate-looking path segments or query strings "
                        "to obscure the true destination and confuse users."
                    ),
                )
            )

        # 2. Deep subdomain nesting
        if len(nesting_items) == 1:
            evidence.append(nesting_items[0])
        elif len(nesting_items) > 1:
            evidence.append(
                EvidenceItem(
                    type="deep_subdomain_nesting",
                    source="heuristics",
                    severity="low",
                    explanation=(
                        f"{len(nesting_items)} links in this email contain deeply nested subdomains (3 or more levels). "
                        "Attackers frequently use deeply nested subdomains to disguise malicious destinations "
                        "as legitimate services."
                    ),
                )
            )

        # 3. Excessive hyphens
        if len(hyphen_items) == 1:
            evidence.append(hyphen_items[0])
        elif len(hyphen_items) > 1:
            evidence.append(
                EvidenceItem(
                    type="excessive_hyphens",
                    source="heuristics",
                    severity="low",
                    explanation=(
                        f"{len(hyphen_items)} links in this email contain 3 or more hyphens in their hostname. "
                        "Attackers frequently insert multiple hyphens into domain names to mimic "
                        "legitimate brand names or create confusing subdomains."
                    ),
                )
            )

        # 4. At-symbol redirect
        if len(at_items) == 1:
            evidence.append(at_items[0])
        elif len(at_items) > 1:
            evidence.append(
                EvidenceItem(
                    type="at_symbol_redirect",
                    source="heuristics",
                    severity="high",
                    explanation=(
                        f"{len(at_items)} links in this email contain an '@' symbol in their authority component. "
                        "Browsers interpret the part after '@' as the real host, allowing attackers to place "
                        "a trusted domain name before '@' to deceive users."
                    ),
                )
            )

        # 5. Other link evidence items (ip_hostname, punycode_lookalike, misleading_subdomain)
        # Deduplicate identical findings
        handled_structural_types = {
            "url_excessive_length",
            "deep_subdomain_nesting",
            "excessive_hyphens",
            "at_symbol_redirect",
        }
        seen_keys: set[tuple[str, str]] = set()
        for item in raw_link_evidence:
            if item.type in handled_structural_types:
                continue
            key = (item.type, item.explanation)
            if key not in seen_keys:
                seen_keys.add(key)
                evidence.append(item)

        # Combine subject and body for text-level analysis
        text_parts: list[str] = []
        if subject:
            text_parts.append(subject)
        if body_text:
            text_parts.append(body_text)
        combined_text = " ".join(text_parts) if text_parts else None

        evidence.extend(detect_urgency_and_credential_language(combined_text))

        return evidence
