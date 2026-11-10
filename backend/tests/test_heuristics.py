"""Tests for the deterministic URL and text heuristics engine.

Test philosophy:
- Every detector has at minimum one positive (detects a finding), one negative
  (clean input produces no finding), and one edge-case test.
- Legitimate domains that contain brand-name keywords are explicitly tested to
  verify false-positive prevention (e.g. checkout.paypal.com must NOT trigger
  the misleading-subdomain detector).
- Network calls are prohibited; a monkeypatch guard ensures offline purity.
- All EvidenceItem fields are verified for correctness, not just presence.
"""

from __future__ import annotations

import socket
import urllib.request

import pytest

from backend.app.detection.heuristics import (
    DeterministicHeuristicsEngine,
    detect_ip_hostname,
    detect_misleading_subdomains,
    detect_punycode_and_lookalike,
    detect_urgency_and_credential_language,
    detect_url_structure_anomalies,
)
from backend.app.schemas.scan import EvidenceItem


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def types_of(items: list[EvidenceItem]) -> list[str]:
    """Return the list of evidence type strings for compact assertions."""
    return [item.type for item in items]


def assert_evidence_item(item: EvidenceItem, *, expected_type: str, expected_severity: str) -> None:
    """Assert that an EvidenceItem has the expected core fields."""
    assert item.type == expected_type, f"Expected type '{expected_type}', got '{item.type}'"
    assert item.source == "heuristics", f"Expected source 'heuristics', got '{item.source}'"
    assert item.severity == expected_severity, (
        f"Expected severity '{expected_severity}', got '{item.severity}'"
    )
    assert isinstance(item.explanation, str) and len(item.explanation) > 10, (
        "Explanation must be a non-trivial string"
    )


# ---------------------------------------------------------------------------
# Network isolation guard — all heuristic tests must be offline
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def block_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail any test that makes a real network call during heuristic evaluation."""

    def blocked_socket(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise AssertionError(
            "Network socket call attempted inside heuristics tests — heuristics must be 100% offline."
        )

    def blocked_urlopen(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise AssertionError(
            "HTTP request attempted inside heuristics tests — heuristics must be 100% offline."
        )

    monkeypatch.setattr(socket, "socket", blocked_socket)
    monkeypatch.setattr(urllib.request, "urlopen", blocked_urlopen)


# ===========================================================================
# 1. detect_ip_hostname
# ===========================================================================

class TestDetectIpHostname:
    """Tests for the IP-as-hostname detector."""

    # --- Positive: IP address triggers detection ---

    def test_ipv4_http(self):
        result = detect_ip_hostname("http://192.168.1.50/login")
        assert result is not None
        assert_evidence_item(result, expected_type="ip_hostname", expected_severity="high")
        assert "192.168.1.50" in result.explanation

    def test_ipv4_public_with_path(self):
        result = detect_ip_hostname("https://203.0.113.5/secure/verify")
        assert result is not None
        assert_evidence_item(result, expected_type="ip_hostname", expected_severity="high")

    def test_ipv4_with_port(self):
        result = detect_ip_hostname("http://10.0.0.1:8080/admin")
        assert result is not None
        assert_evidence_item(result, expected_type="ip_hostname", expected_severity="high")

    def test_ipv6_loopback(self):
        result = detect_ip_hostname("http://[::1]/test")
        assert result is not None
        assert_evidence_item(result, expected_type="ip_hostname", expected_severity="high")

    def test_ipv6_full_address(self):
        result = detect_ip_hostname("https://[2001:db8::1]/path")
        assert result is not None
        assert_evidence_item(result, expected_type="ip_hostname", expected_severity="high")

    # --- Negative: Named domain returns None ---

    def test_clean_named_domain(self):
        assert detect_ip_hostname("https://example.com") is None

    def test_www_domain(self):
        assert detect_ip_hostname("https://www.paypal.com/login") is None

    def test_subdomain_with_numbers(self):
        # Hostnames with numeric segments are not IPs
        assert detect_ip_hostname("https://m1.bank.co.uk/home") is None

    # --- Edge cases ---

    def test_looks_like_ip_but_is_not(self):
        # 999.999.999.999 is not a valid IP
        assert detect_ip_hostname("http://999.999.999.999/path") is None

    def test_url_without_host(self):
        # Malformed URL: no host — should return None gracefully, not crash
        result = detect_ip_hostname("http:///no-host/path")
        assert result is None

    def test_loopback_127(self):
        result = detect_ip_hostname("http://127.0.0.1:8000/login")
        assert result is not None
        assert_evidence_item(result, expected_type="ip_hostname", expected_severity="high")


# ===========================================================================
# 2. detect_punycode_and_lookalike
# ===========================================================================

class TestDetectPunycodeAndLookalike:
    """Tests for the Punycode homoglyph detector."""

    # --- Positive ---

    def test_punycode_paypal_lookalike(self):
        # xn--pypal-4ve.com is the Punycode encoding of 'pаypal.com' (Cyrillic 'а')
        result = detect_punycode_and_lookalike("xn--pypal-4ve.com")
        assert result is not None
        assert_evidence_item(result, expected_type="punycode_homoglyph", expected_severity="high")
        assert "xn--pypal-4ve" in result.explanation

    def test_punycode_label_in_subdomain(self):
        result = detect_punycode_and_lookalike("xn--googl-kua.com")
        assert result is not None
        assert_evidence_item(result, expected_type="punycode_homoglyph", expected_severity="high")

    def test_punycode_in_middle_label(self):
        result = detect_punycode_and_lookalike("secure.xn--mcrosft-n2a.com")
        assert result is not None
        assert_evidence_item(result, expected_type="punycode_homoglyph", expected_severity="high")

    def test_legitimate_idn_country_domain(self):
        # xn--e1afmkfd.xn--p1ai = пример.рф (Russian language legitimate domain)
        # We still flag it — the caller decides on context; our job is to surface the signal
        result = detect_punycode_and_lookalike("xn--e1afmkfd.xn--p1ai")
        assert result is not None
        assert result.type == "punycode_homoglyph"

    # --- Negative ---

    def test_clean_ascii_domain(self):
        assert detect_punycode_and_lookalike("paypal.com") is None

    def test_subdomain_clean(self):
        assert detect_punycode_and_lookalike("login.microsoft.com") is None

    def test_domain_with_numbers_no_punycode(self):
        assert detect_punycode_and_lookalike("secure2.bank.co.uk") is None

    # --- Edge cases ---

    def test_xn_prefix_in_domain_label_not_starting(self):
        # 'myxn--site.com' — 'xn--' does not appear at start of a label, so no match
        result = detect_punycode_and_lookalike("myxn--site.com")
        assert result is None

    def test_empty_hostname(self):
        assert detect_punycode_and_lookalike("") is None

    def test_single_label(self):
        assert detect_punycode_and_lookalike("localhost") is None


# ===========================================================================
# 3. detect_misleading_subdomains
# ===========================================================================

class TestDetectMisleadingSubdomains:
    """Tests for the misleading-subdomain brand-impersonation detector."""

    # --- Positive: brand in subdomain, registered domain is not that brand ---

    def test_paypal_in_evil_subdomain(self):
        items = detect_misleading_subdomains(
            "https://paypal.com.account-update.xyz/login"
        )
        assert len(items) == 1
        assert_evidence_item(items[0], expected_type="misleading_subdomain", expected_severity="high")
        assert "paypal" in items[0].explanation

    def test_google_in_phish_subdomain(self):
        items = detect_misleading_subdomains("https://google.com.phish.cc/verify")
        assert len(items) == 1
        assert_evidence_item(items[0], expected_type="misleading_subdomain", expected_severity="high")
        assert "google" in items[0].explanation

    def test_apple_in_subdomain_different_registrar(self):
        items = detect_misleading_subdomains("https://apple-secure.badactor.net/reset-password")
        assert len(items) == 1
        assert_evidence_item(items[0], expected_type="misleading_subdomain", expected_severity="high")

    def test_microsoft_login_phish(self):
        items = detect_misleading_subdomains("https://microsoft.login.update-required.org")
        assert len(items) == 1
        assert_evidence_item(items[0], expected_type="misleading_subdomain", expected_severity="high")

    def test_amazon_subdomain_spoofing(self):
        items = detect_misleading_subdomains("https://amazon.verify.account-protect.ru/signin")
        assert len(items) == 1
        assert_evidence_item(items[0], expected_type="misleading_subdomain", expected_severity="high")

    # --- Negative: brand IS the registered domain (legitimate) ---

    def test_legitimate_paypal_checkout_subdomain(self):
        """checkout.paypal.com is LEGITIMATE — must NOT trigger detection."""
        items = detect_misleading_subdomains("https://checkout.paypal.com/pay")
        assert items == [], (
            f"False positive: checkout.paypal.com triggered misleading_subdomain: {items}"
        )

    def test_legitimate_login_google(self):
        """login.google.com is LEGITIMATE — must NOT trigger."""
        items = detect_misleading_subdomains("https://login.google.com/oauth")
        assert items == [], (
            f"False positive: login.google.com triggered misleading_subdomain: {items}"
        )

    def test_legitimate_apple_support(self):
        """support.apple.com is LEGITIMATE — must NOT trigger."""
        items = detect_misleading_subdomains("https://support.apple.com/kb/HT1234")
        assert items == []

    def test_legitimate_microsoft_office(self):
        """office.microsoft.com is LEGITIMATE — must NOT trigger."""
        items = detect_misleading_subdomains("https://office.microsoft.com/en-us/")
        assert items == []

    def test_legitimate_amazon_aws(self):
        """s3.amazonaws.com is LEGITIMATE — must NOT trigger (amazon not in subdomain)."""
        items = detect_misleading_subdomains("https://bucket.s3.amazonaws.com/file")
        assert items == []

    def test_no_subdomain_clean_domain(self):
        items = detect_misleading_subdomains("https://wikipedia.org/wiki/Phishing")
        assert items == []

    def test_clean_site_no_brand(self):
        items = detect_misleading_subdomains("https://en.wikipedia.org/wiki/Security")
        assert items == []

    def test_false_positives_avoided_words_containing_brands(self):
        """Words containing brand substrings or single-letter 'x' must NOT trigger false positives."""
        safe_urls = [
            "https://max.example.com",
            "https://next.example.com",
            "https://purchase.store.com",
            "https://pineapple.food.com",
            "https://linux.example.org",
            "https://proxy.company.com",
            "https://tax.service.gov",
        ]
        for url in safe_urls:
            items = detect_misleading_subdomains(url)
            assert items == [], f"False positive triggered for safe URL '{url}': {items}"

    def test_hyphenated_and_tokenized_brand_subdomains_detected(self):
        """Brand keywords separated by dots or hyphens must be reliably detected."""
        phish_urls = [
            ("https://paypal-login.security-update.xyz/signin", "paypal"),
            ("https://apple-id.verify.xyz/auth", "apple"),
            ("https://chase-security.update.com/login", "chase"),
            ("https://login.paypal.verify.phish.org/account", "paypal"),
        ]
        for url, expected_brand in phish_urls:
            items = detect_misleading_subdomains(url)
            assert any(i.type == "misleading_subdomain" for i in items), f"Missed brand for '{url}'"
            item = next(i for i in items if i.type == "misleading_subdomain")
            assert expected_brand in item.explanation

    # --- Edge cases ---

    def test_ip_address_url_skipped(self):
        """IP address URLs have no subdomain — must not crash or false-positive."""
        items = detect_misleading_subdomains("http://192.168.1.1/paypal-login")
        # Registered domain is 192.168.1.1, subdomain is empty → no misleading subdomain
        assert items == []

    def test_brand_in_path_not_subdomain(self):
        """Brand in path only (not subdomain) should not trigger detection."""
        items = detect_misleading_subdomains("https://evil.com/paypal/login")
        assert items == []

    def test_invalid_url_does_not_raise(self):
        """Invalid URLs must be gracefully skipped, not raise exceptions."""
        items = detect_misleading_subdomains("not-a-url-at-all")
        # May or may not return items; must NOT raise
        assert isinstance(items, list)


# ===========================================================================
# 4. detect_url_structure_anomalies
# ===========================================================================

class TestDetectUrlStructureAnomalies:
    """Tests for URL structural anomaly detection."""

    # --- url_excessive_length ---

    def test_url_exceeding_100_chars(self):
        long_url = "https://secure-bank-login-verify-account.com/" + "a" * 80
        items = detect_url_structure_anomalies(long_url)
        assert any(i.type == "url_excessive_length" for i in items)
        item = next(i for i in items if i.type == "url_excessive_length")
        assert_evidence_item(item, expected_type="url_excessive_length", expected_severity="low")

    def test_url_exactly_100_chars_not_flagged(self):
        # Exactly 100 characters: 'https://example.com/' (20) + 80 'a's
        url = "https://example.com/" + "a" * 80  # 100 chars
        items = detect_url_structure_anomalies(url)
        assert not any(i.type == "url_excessive_length" for i in items)

    def test_url_101_chars_flagged(self):
        url = "https://example.com/" + "a" * 81  # 101 chars
        items = detect_url_structure_anomalies(url)
        assert any(i.type == "url_excessive_length" for i in items)

    def test_short_clean_url_not_flagged(self):
        items = detect_url_structure_anomalies("https://en.wikipedia.org/wiki/Security")
        assert not any(i.type == "url_excessive_length" for i in items)

    # --- at_symbol_redirect ---

    def test_at_symbol_in_authority(self):
        url = "https://trusted-bank.com@evil-redirect.net/phish"
        items = detect_url_structure_anomalies(url)
        assert any(i.type == "at_symbol_redirect" for i in items)
        item = next(i for i in items if i.type == "at_symbol_redirect")
        assert_evidence_item(item, expected_type="at_symbol_redirect", expected_severity="high")

    def test_at_symbol_with_credentials(self):
        url = "http://user@password@evil.com/login"
        items = detect_url_structure_anomalies(url)
        assert any(i.type == "at_symbol_redirect" for i in items)

    def test_at_symbol_in_query_string_only_not_flagged(self):
        # '@' in query param only — netloc won't contain it
        url = "https://example.com/search?q=user@domain"
        items = detect_url_structure_anomalies(url)
        assert not any(i.type == "at_symbol_redirect" for i in items)

    def test_clean_url_no_at_symbol(self):
        items = detect_url_structure_anomalies("https://example.com/login")
        assert not any(i.type == "at_symbol_redirect" for i in items)

    # --- excessive_hyphens ---

    def test_three_hyphens_flagged(self):
        # 3 hyphens total: secure-login-verify-now.com
        url = "https://secure-login-verify-now.com/account"
        items = detect_url_structure_anomalies(url)
        assert any(i.type == "excessive_hyphens" for i in items)
        item = next(i for i in items if i.type == "excessive_hyphens")
        assert_evidence_item(item, expected_type="excessive_hyphens", expected_severity="low")

    def test_two_hyphens_not_flagged(self):
        # Exactly 2 hyphens: my-cool-site.com — should NOT trigger
        url = "https://my-cool-site.com/page"
        items = detect_url_structure_anomalies(url)
        assert not any(i.type == "excessive_hyphens" for i in items)

    def test_no_hyphens_clean(self):
        items = detect_url_structure_anomalies("https://example.com/path")
        assert not any(i.type == "excessive_hyphens" for i in items)

    def test_punycode_xn_prefix_does_not_inflate_hyphens(self):
        """Punycode prefix 'xn--' should not count towards deceptive hyphens."""
        # xn--pypal-4ve.com has 3 hyphens in raw text (2 in xn--, 1 in -4ve),
        # but only 1 deceptive hyphen once xn-- is stripped.
        items = detect_url_structure_anomalies("http://xn--pypal-4ve.com/path")
        assert not any(i.type == "excessive_hyphens" for i in items)

    def test_punycode_with_actual_excessive_hyphens_still_flagged(self):
        """Punycode host with > 2 additional hyphens is correctly flagged."""
        # 3 hyphens in body: a-b-c
        items = detect_url_structure_anomalies("http://xn--a-b-c-123.com/path")
        assert any(i.type == "excessive_hyphens" for i in items)

    # --- deep_subdomain_nesting ---

    def test_four_labels_flagged(self):
        url = "https://login.secure.bank.example.com/auth"
        items = detect_url_structure_anomalies(url)
        assert any(i.type == "deep_subdomain_nesting" for i in items)
        item = next(i for i in items if i.type == "deep_subdomain_nesting")
        assert_evidence_item(item, expected_type="deep_subdomain_nesting", expected_severity="low")

    def test_three_labels_not_flagged(self):
        # www.paypal.com → 1 subdomain level, no flag
        items = detect_url_structure_anomalies("https://www.paypal.com/checkout")
        assert not any(i.type == "deep_subdomain_nesting" for i in items)

    def test_five_labels_flagged(self):
        url = "https://a.b.c.d.example.com/path"
        items = detect_url_structure_anomalies(url)
        assert any(i.type == "deep_subdomain_nesting" for i in items)

    def test_multipart_public_suffixes_not_flagged_as_deep_nesting(self):
        """Ordinary domains with multi-part ccTLDs must NOT be flagged as deep nesting."""
        safe_cctld_urls = [
            "https://www.example.co.uk",
            "https://www.example.com.au",
            "https://www.example.co.jp",
            "https://sub.example.co.uk/page",
            "https://portal.bank.com.au/login",
        ]
        for url in safe_cctld_urls:
            items = detect_url_structure_anomalies(url)
            assert not any(i.type == "deep_subdomain_nesting" for i in items), (
                f"False positive deep nesting on ccTLD '{url}': {items}"
            )

    def test_genuinely_deep_nesting_on_cctld_flagged(self):
        """Domains with >= 3 actual subdomain levels on ccTLDs MUST be flagged."""
        deep_url = "https://a.b.c.example.co.uk/path"
        items = detect_url_structure_anomalies(deep_url)
        assert any(i.type == "deep_subdomain_nesting" for i in items)

    # --- Clean URL produces no anomalies ---

    def test_wikipedia_clean(self):
        """A well-known clean URL should produce zero anomaly findings."""
        items = detect_url_structure_anomalies("https://en.wikipedia.org/wiki/Security")
        assert items == [], f"Unexpected anomalies on Wikipedia URL: {items}"

    def test_google_clean(self):
        items = detect_url_structure_anomalies("https://www.google.com/search?q=phishing")
        assert items == [], f"Unexpected anomalies on Google URL: {items}"


# ===========================================================================
# 5. detect_urgency_and_credential_language
# ===========================================================================

class TestDetectUrgencyAndCredentialLanguage:
    """Tests for urgency and credential-harvesting language detection."""

    # --- urgency_language positives ---

    def test_account_suspended(self):
        items = detect_urgency_and_credential_language(
            "Your account has been suspended. Please verify immediately."
        )
        assert any(i.type == "urgency_language" for i in items)
        item = next(i for i in items if i.type == "urgency_language")
        assert_evidence_item(item, expected_type="urgency_language", expected_severity="medium")

    def test_account_locked(self):
        items = detect_urgency_and_credential_language("Your account has been locked.")
        assert any(i.type == "urgency_language" for i in items)

    def test_immediate_action_required(self):
        items = detect_urgency_and_credential_language(
            "IMMEDIATE ACTION REQUIRED: log in to verify your identity."
        )
        assert any(i.type == "urgency_language" for i in items)

    def test_verify_within_hours(self):
        items = detect_urgency_and_credential_language(
            "Please verify your account within 24 hours to avoid suspension."
        )
        assert any(i.type == "urgency_language" for i in items)

    def test_unusual_signin_detected(self):
        items = detect_urgency_and_credential_language(
            "We noticed an unusual sign-in attempt from a new device."
        )
        assert any(i.type == "urgency_language" for i in items)

    def test_update_payment_now(self):
        items = detect_urgency_and_credential_language(
            "Update your payment information now to continue using the service."
        )
        assert any(i.type == "urgency_language" for i in items)

    # --- credential_harvesting_language positives ---

    def test_verify_password(self):
        items = detect_urgency_and_credential_language(
            "Please verify your password to continue."
        )
        assert any(i.type == "credential_harvesting_language" for i in items)
        item = next(i for i in items if i.type == "credential_harvesting_language")
        assert_evidence_item(
            item,
            expected_type="credential_harvesting_language",
            expected_severity="medium",
        )

    def test_enter_ssn(self):
        items = detect_urgency_and_credential_language(
            "Enter your Social Security number to validate your identity."
        )
        assert any(i.type == "credential_harvesting_language" for i in items)

    def test_confirm_pin(self):
        items = detect_urgency_and_credential_language(
            "Please confirm your PIN to proceed."
        )
        assert any(i.type == "credential_harvesting_language" for i in items)

    def test_enter_credit_card(self):
        items = detect_urgency_and_credential_language(
            "Enter your full credit card number below to verify."
        )
        assert any(i.type == "credential_harvesting_language" for i in items)

    def test_reenter_password(self):
        items = detect_urgency_and_credential_language(
            "For security reasons, please re-enter your password."
        )
        assert any(i.type == "credential_harvesting_language" for i in items)

    # --- No match on clean professional text ---

    def test_clean_email_text(self):
        items = detect_urgency_and_credential_language(
            "Thank you for your order. Your package will arrive in 3-5 business days."
        )
        assert items == [], f"False positive on clean text: {items}"

    def test_security_article_text(self):
        items = detect_urgency_and_credential_language(
            "Phishing attacks often impersonate banks. Always check the URL before entering any information."
        )
        assert items == [], f"False positive on security article text: {items}"

    def test_none_text(self):
        assert detect_urgency_and_credential_language(None) == []

    def test_empty_string(self):
        assert detect_urgency_and_credential_language("") == []

    def test_whitespace_only(self):
        assert detect_urgency_and_credential_language("   \n\t  ") == []

    # --- Multiple matches: only one urgency and one credential finding reported ---

    def test_multiple_urgency_signals_produces_single_finding(self):
        text = (
            "Your account has been suspended. "
            "Immediate action is required to avoid account deletion. "
            "Verify within 24 hours."
        )
        items = detect_urgency_and_credential_language(text)
        urgency_items = [i for i in items if i.type == "urgency_language"]
        assert len(urgency_items) == 1, (
            f"Expected exactly 1 urgency finding, got {len(urgency_items)}"
        )

    def test_both_urgency_and_credential_signals(self):
        text = (
            "Your account has been suspended. "
            "Please verify your password to reactivate."
        )
        items = detect_urgency_and_credential_language(text)
        types = types_of(items)
        assert "urgency_language" in types
        assert "credential_harvesting_language" in types


# ===========================================================================
# 6. DeterministicHeuristicsEngine — integration-style tests
# ===========================================================================

class TestDeterministicHeuristicsEngineWebsite:
    """Integration tests for DeterministicHeuristicsEngine.analyze_website."""

    def setup_method(self) -> None:
        self.engine = DeterministicHeuristicsEngine()

    def test_clean_wikipedia_produces_no_evidence(self):
        """A well-known clean URL must produce an empty evidence list."""
        evidence = self.engine.analyze_website(
            url="https://en.wikipedia.org/wiki/Security",
            target_reference="en.wikipedia.org",
            page_title="Security — Wikipedia",
            visible_text="Phishing is a type of social engineering attack.",
        )
        assert evidence == [], (
            f"Expected empty evidence for Wikipedia, got: {evidence}"
        )

    def test_ip_url_produces_ip_evidence(self):
        evidence = self.engine.analyze_website(
            url="http://192.168.1.50/login",
            target_reference="192.168.1.50",
        )
        assert any(e.type == "ip_hostname" for e in evidence)

    def test_misleading_subdomain_phishing_url(self):
        evidence = self.engine.analyze_website(
            url="https://paypal.com.account-update.xyz/login",
            target_reference="paypal.com.account-update.xyz",
        )
        assert any(e.type == "misleading_subdomain" for e in evidence)

    def test_punycode_url_produces_evidence(self):
        evidence = self.engine.analyze_website(
            url="https://xn--pypal-4ve.com/login",
            target_reference="xn--pypal-4ve.com",
        )
        assert any(e.type == "punycode_homoglyph" for e in evidence)

    def test_urgent_page_text_produces_evidence(self):
        evidence = self.engine.analyze_website(
            url="https://legit-looking-bank.com/secure",
            target_reference="legit-looking-bank.com",
            visible_text="Your account has been suspended. Verify now.",
        )
        assert any(e.type == "urgency_language" for e in evidence)

    def test_credential_page_text_produces_evidence(self):
        evidence = self.engine.analyze_website(
            url="https://bank-verify.com/auth",
            target_reference="bank-verify.com",
            visible_text="Enter your password to reactivate your account.",
        )
        assert any(e.type == "credential_harvesting_language" for e in evidence)

    def test_at_symbol_redirect_url(self):
        evidence = self.engine.analyze_website(
            url="https://trusted-bank.com@evil.net/phish",
            target_reference="evil.net",
        )
        assert any(e.type == "at_symbol_redirect" for e in evidence)

    def test_highly_suspicious_composite_url(self):
        """URL with multiple signals produces multiple evidence items."""
        url = "https://paypal.com.secure-login-verify-now.xyz/confirm?token=" + "A" * 200
        evidence = self.engine.analyze_website(
            url=url,
            target_reference="paypal.com.secure-login-verify-now.xyz",
            visible_text="Verify your account within 24 hours. Enter your password below.",
        )
        found_types = types_of(evidence)
        assert "misleading_subdomain" in found_types
        assert "url_excessive_length" in found_types
        assert "urgency_language" in found_types or "credential_harvesting_language" in found_types

    def test_no_title_no_text_does_not_crash(self):
        """Engine must handle None title and text gracefully."""
        evidence = self.engine.analyze_website(
            url="https://example.com",
            target_reference="example.com",
            page_title=None,
            visible_text=None,
        )
        assert isinstance(evidence, list)

    def test_all_evidence_items_are_valid_schema(self):
        """All returned items must conform to the EvidenceItem Pydantic schema."""
        url = "https://google.account-security.malicious-host.org/verify-now?redirect=" + "x" * 150
        evidence = self.engine.analyze_website(
            url=url,
            target_reference="google.account-security.malicious-host.org",
            visible_text="Immediate action required. Enter your password.",
        )
        for item in evidence:
            assert isinstance(item, EvidenceItem)
            assert item.type
            assert item.source == "heuristics"
            assert item.severity in {"low", "medium", "high"}
            assert item.explanation


class TestDeterministicHeuristicsEngineEmail:
    """Integration tests for DeterministicHeuristicsEngine.analyze_email."""

    def setup_method(self) -> None:
        self.engine = DeterministicHeuristicsEngine()

    def test_clean_email_no_evidence(self):
        evidence = self.engine.analyze_email(
            sender="newsletter@company.com",
            subject="Your weekly digest",
            body_text="Here are the top stories this week. Click to read more.",
            links=["https://company.com/news/2024", "https://company.com/unsubscribe"],
        )
        assert evidence == [], f"Expected no evidence for clean email, got: {evidence}"

    def test_phishing_email_with_ip_link(self):
        evidence = self.engine.analyze_email(
            sender="no-reply@update-service.com",
            subject="Action required",
            body_text="Click below to verify your account.",
            links=["http://203.0.113.5/phish"],
        )
        assert any(e.type == "ip_hostname" for e in evidence)

    def test_phishing_email_misleading_link(self):
        evidence = self.engine.analyze_email(
            sender="support@paypal.com.evil.org",
            subject="Account issue",
            body_text="Please log in to resolve your account issue.",
            links=["https://paypal.com.account-verify.xyz/login"],
        )
        assert any(e.type == "misleading_subdomain" for e in evidence)

    def test_phishing_email_urgent_subject(self):
        evidence = self.engine.analyze_email(
            sender="security@bank.com",
            subject="Your account has been suspended — immediate action required",
            body_text=None,
            links=[],
        )
        assert any(e.type == "urgency_language" for e in evidence)

    def test_credential_harvesting_in_body(self):
        evidence = self.engine.analyze_email(
            sender="alerts@bank-security.info",
            subject="Security notice",
            body_text="For verification, please confirm your PIN and bank account number.",
            links=[],
        )
        assert any(e.type == "credential_harvesting_language" for e in evidence)

    def test_punycode_link_detected(self):
        evidence = self.engine.analyze_email(
            sender="noreply@example.com",
            subject="Click the link below",
            body_text="Please visit the following link.",
            links=["https://xn--pypal-4ve.com/verify"],
        )
        assert any(e.type == "punycode_homoglyph" for e in evidence)

    def test_no_links_no_body_does_not_crash(self):
        evidence = self.engine.analyze_email(
            sender=None, subject=None, body_text=None, links=None
        )
        assert isinstance(evidence, list)

    def test_empty_links_list(self):
        evidence = self.engine.analyze_email(
            sender="legit@company.com",
            subject="Hi there",
            body_text="Have a great day!",
            links=[],
        )
        assert evidence == []


# ===========================================================================
# 8. Scoring correctness and false-positive regression tests
# ===========================================================================

class TestScoringAndFalsePositiveRegression:
    """
    Regression tests verifying that:
    - Correlated structural URL signals from ONE URL do not inflate the score
      disproportionately.
    - url_excessive_length alone produces only a low-severity indicator.
    - deep_subdomain_nesting alone produces only a low-severity indicator.
    - Legitimate transactional, unsubscribe, and account-setup URLs with long
      query strings are detected but do not escalate beyond the low-severity
      support-signal level.
    - Independent high-confidence phishing signals (misleading_subdomain,
      ip_hostname, punycode_homoglyph, at_symbol_redirect) remain strong
      and are unaffected by the structural-signal severity adjustment.
    """

    def setup_method(self) -> None:
        self.engine = DeterministicHeuristicsEngine()

    # -----------------------------------------------------------------------
    # Severity checks — confirm expected severity levels
    # -----------------------------------------------------------------------

    def test_url_excessive_length_severity_is_low(self):
        """url_excessive_length must carry 'low' severity (not medium) to avoid
        disproportionate score contribution when combined with other structural signals."""
        long_url = "https://accounts.example.com/setup?" + "x=" * 50 + "token=abc123"
        items = detect_url_structure_anomalies(long_url)
        length_items = [i for i in items if i.type == "url_excessive_length"]
        assert length_items, "Expected url_excessive_length to fire on a long URL"
        for item in length_items:
            assert item.severity == "low", (
                f"url_excessive_length severity must be 'low', got '{item.severity}'. "
                "URL length is a weak structural signal that fires on legitimate "
                "transactional, tracking, and account-setup URLs."
            )

    def test_deep_subdomain_nesting_severity_is_low(self):
        """deep_subdomain_nesting must carry 'low' severity (not medium) because many
        legitimate services use multi-level subdomain hierarchies."""
        url = "https://login.secure.bank.example.com/auth"
        items = detect_url_structure_anomalies(url)
        nesting_items = [i for i in items if i.type == "deep_subdomain_nesting"]
        assert nesting_items, "Expected deep_subdomain_nesting to fire"
        for item in nesting_items:
            assert item.severity == "low", (
                f"deep_subdomain_nesting severity must be 'low', got '{item.severity}'."
            )

    # -----------------------------------------------------------------------
    # Score inflation regression — correlated structural signals
    # -----------------------------------------------------------------------

    def test_three_correlated_structural_signals_from_one_url_score_at_most_35(self):
        """When url_excessive_length + deep_subdomain_nesting + excessive_hyphens all
        fire from the same URL, the combined heuristic score must not exceed 35.
        (All three are 'low' severity: strongest=25 + 2 extra items * 5 = 35.)
        This prevents a 284-character legitimate Google transactional link from
        producing a disproportionately high risk score of 60."""
        from backend.app.detection.orchestrator import RealDetectionOrchestrator
        from backend.app.schemas.scan import EvidenceItem, ToolStatusDetail

        orch = RealDetectionOrchestrator()
        # Construct exactly three low-severity structural items (all from one URL)
        structural_evidence = [
            EvidenceItem(
                type="url_excessive_length",
                source="heuristics",
                severity="low",
                explanation="Long URL structural signal.",
            ),
            EvidenceItem(
                type="deep_subdomain_nesting",
                source="heuristics",
                severity="low",
                explanation="Deep nesting structural signal.",
            ),
            EvidenceItem(
                type="excessive_hyphens",
                source="heuristics",
                severity="low",
                explanation="Excessive hyphens structural signal.",
            ),
        ]
        result = orch._combine(
            evidence=structural_evidence,
            llm_result=None,
            llm_status=ToolStatusDetail(status="unavailable", reason_code="opt_in_required"),
        )
        assert result.risk_score is not None
        assert result.risk_score <= 35, (
            f"Three correlated structural low-severity signals must score at most 35, "
            f"got {result.risk_score}. This prevents legitimate long URLs from being "
            "incorrectly flagged with high risk scores."
        )

    def test_url_length_alone_scores_at_most_25(self):
        """A single url_excessive_length finding must score at most 25 (low base, 0 bonus).
        A long URL alone must not drive a risk score that triggers suspicious classification
        without supporting evidence."""
        from backend.app.detection.orchestrator import RealDetectionOrchestrator
        from backend.app.schemas.scan import EvidenceItem, ToolStatusDetail

        orch = RealDetectionOrchestrator()
        evidence = [
            EvidenceItem(
                type="url_excessive_length",
                source="heuristics",
                severity="low",
                explanation="Long URL.",
            )
        ]
        result = orch._combine(
            evidence=evidence,
            llm_result=None,
            llm_status=ToolStatusDetail(status="unavailable", reason_code="opt_in_required"),
        )
        assert result.risk_score is not None
        assert result.risk_score <= 25, (
            f"URL length alone must score at most 25, got {result.risk_score}."
        )

    # -----------------------------------------------------------------------
    # Legitimate URL false-positive regression
    # -----------------------------------------------------------------------

    def test_legitimate_account_setup_url_does_not_produce_excessive_score(self):
        """A realistic 284-character Google account-setup URL with a long token and
        parameters must produce evidence (url_excessive_length) but NOT score above 35."""
        from backend.app.detection.orchestrator import RealDetectionOrchestrator
        from backend.app.schemas.scan import ToolStatusDetail

        # Realistic-looking account-setup / verification URL with a long token
        url = (
            "https://accounts.google.com/o/oauth2/auth?client_id=1234567890"
            "&redirect_uri=https%3A%2F%2Fmail.google.com%2Foauth2%2Fcallback"
            "&response_type=code&scope=openid+email+profile"
            "&state=CSRF_TOKEN_PLACEHOLDER_xyzxyzxyz"
            "&nonce=NONCE_VALUE_abcdefghijklmnopqrstuvwxyz"
            "&prompt=select_account"
        )
        assert len(url) > 100, f"Test URL is too short ({len(url)} chars), adjust it"

        orch = RealDetectionOrchestrator()
        # Only run heuristics directly
        evidence = self.engine.analyze_email(
            sender="no-reply@google.com",
            subject="Set up your Google account",
            body_text="Click the link to complete account setup.",
            links=[url],
        )

        # url_excessive_length should fire
        length_ev = [e for e in evidence if e.type == "url_excessive_length"]
        assert length_ev, "Expected url_excessive_length for a >100 char URL"

        # Score should not be excessive
        llm_status = ToolStatusDetail(status="unavailable", reason_code="opt_in_required")
        result = orch._combine(evidence=evidence, llm_result=None, llm_status=llm_status)
        assert result.risk_score is not None
        assert result.risk_score <= 35, (
            f"Legitimate account-setup URL scored {result.risk_score} — "
            "must not exceed 35 for a correlated structural-signal group."
        )

    def test_legitimate_unsubscribe_url_does_not_produce_excessive_score(self):
        """A realistic long unsubscribe URL (common in bulk email) with a UUID token
        must not produce a disproportionate risk score."""
        from backend.app.detection.orchestrator import RealDetectionOrchestrator
        from backend.app.schemas.scan import ToolStatusDetail

        url = (
            "https://email.company.com/unsubscribe"
            "?token=a1b2c3d4-e5f6-7890-abcd-ef1234567890"
            "&list=newsletter"
            "&user=encoded_user_id_placeholder_12345"
            "&sig=HMAC_SIGNATURE_VALUE_PLACEHOLDER_abcdef"
        )
        assert len(url) > 100

        orch = RealDetectionOrchestrator()
        evidence = self.engine.analyze_email(
            sender="newsletter@company.com",
            subject="Your weekly digest",
            body_text="Unsubscribe from this list.",
            links=[url],
        )
        llm_status = ToolStatusDetail(status="unavailable", reason_code="opt_in_required")
        result = orch._combine(evidence=evidence, llm_result=None, llm_status=llm_status)
        # Might score 0 (no evidence) or low if only url_excessive_length fires
        if result.risk_score is not None:
            assert result.risk_score <= 35, (
                f"Legitimate unsubscribe URL scored {result.risk_score} — must not exceed 35."
            )

    def test_legitimate_tracking_url_does_not_produce_excessive_score(self):
        """A realistic long UTM-tracked marketing URL must not score excessively."""
        from backend.app.detection.orchestrator import RealDetectionOrchestrator
        from backend.app.schemas.scan import ToolStatusDetail

        url = (
            "https://www.example.com/products/summer-sale-2024"
            "?utm_source=email&utm_medium=newsletter"
            "&utm_campaign=summer_sale_announcement"
            "&utm_content=cta_button_hero"
            "&utm_term=summer+sale+deals+2024"
            "&ref=email_promo_aug2024"
        )
        assert len(url) > 100

        orch = RealDetectionOrchestrator()
        evidence = self.engine.analyze_email(
            sender="promotions@example.com",
            subject="Summer sale is on!",
            body_text="Shop the summer sale now.",
            links=[url],
        )
        llm_status = ToolStatusDetail(status="unavailable", reason_code="opt_in_required")
        result = orch._combine(evidence=evidence, llm_result=None, llm_status=llm_status)
        if result.risk_score is not None:
            assert result.risk_score <= 35, (
                f"Legitimate tracking URL scored {result.risk_score} — must not exceed 35."
            )

    # -----------------------------------------------------------------------
    # High-confidence signals remain unaffected
    # -----------------------------------------------------------------------

    def test_misleading_subdomain_still_produces_high_severity_evidence(self):
        """misleading_subdomain must remain 'high' severity and drive phishing-level scores."""
        items = detect_misleading_subdomains("https://paypal.com.account-verify.phish.net/login")
        assert items, "Expected misleading_subdomain evidence"
        for item in items:
            assert item.severity == "high", (
                f"misleading_subdomain severity must remain 'high', got '{item.severity}'"
            )

    def test_ip_hostname_still_produces_high_severity_evidence(self):
        """ip_hostname must remain 'high' severity."""
        item = detect_ip_hostname("http://192.168.1.100/phish")
        assert item is not None
        assert item.severity == "high"

    def test_punycode_still_produces_high_severity_evidence(self):
        """punycode_homoglyph must remain 'high' severity."""
        item = detect_punycode_and_lookalike("xn--pypal-4ve.com")
        assert item is not None
        assert item.severity == "high"

    def test_at_symbol_redirect_still_produces_high_severity_evidence(self):
        """at_symbol_redirect must remain 'high' severity."""
        items = detect_url_structure_anomalies("https://trusted.com@evil-redirect.net/phish")
        at_items = [i for i in items if i.type == "at_symbol_redirect"]
        assert at_items, "Expected at_symbol_redirect"
        assert at_items[0].severity == "high"

    def test_phishing_composite_misleading_subdomain_still_reaches_phishing_threshold(self):
        """A URL with misleading_subdomain (high) + url_excessive_length (low) +
        deep_subdomain_nesting (low) must still score >= 70 → phishing."""
        from backend.app.detection.orchestrator import RealDetectionOrchestrator
        from backend.app.schemas.scan import EvidenceItem, ToolStatusDetail

        orch = RealDetectionOrchestrator()
        evidence = [
            EvidenceItem(
                type="misleading_subdomain",
                source="heuristics",
                severity="high",
                explanation="Subdomain impersonates PayPal.",
            ),
            EvidenceItem(
                type="url_excessive_length",
                source="heuristics",
                severity="low",
                explanation="Long URL.",
            ),
            EvidenceItem(
                type="deep_subdomain_nesting",
                source="heuristics",
                severity="low",
                explanation="Deep nesting.",
            ),
        ]
        result = orch._combine(
            evidence=evidence,
            llm_result=None,
            llm_status=ToolStatusDetail(status="unavailable", reason_code="opt_in_required"),
        )
        assert result.risk_score is not None
        assert result.risk_score >= 70, (
            f"misleading_subdomain + structural signals must reach >= 70, "
            f"got {result.risk_score}. High-confidence signals must not be weakened."
        )
        assert result.classification == "phishing"

    def test_suspicious_nested_subdomains_still_detectable(self):
        """Deep subdomain nesting on a phishing-style domain is still flagged."""
        url = "https://login.secure.verify.paypal-update.xyz/account"
        items = detect_url_structure_anomalies(url)
        nesting = [i for i in items if i.type == "deep_subdomain_nesting"]
        assert nesting, "Deep subdomain nesting on phishing URL must still be detected"

    def test_punycode_and_lookalike_detection_unaffected(self):
        """Punycode detection must be completely unaffected by severity changes."""
        result = detect_punycode_and_lookalike("xn--googl-kua.com")
        assert result is not None
        assert result.type == "punycode_homoglyph"
        assert result.severity == "high"


# ===========================================================================
# 7. EvidenceItem field stability
# ===========================================================================

class TestEvidenceItemFieldStability:
    """Verify that rule identifiers (type field) remain stable across calls.

    These tests are intentionally rigid: changing a rule identifier is a
    breaking change for any consumer serializing EvidenceItem objects.
    """

    EXPECTED_RULE_IDS = {
        "ip_hostname",
        "punycode_homoglyph",
        "misleading_subdomain",
        "url_excessive_length",
        "at_symbol_redirect",
        "excessive_hyphens",
        "deep_subdomain_nesting",
        "urgency_language",
        "credential_harvesting_language",
    }

    def test_ip_hostname_type_id(self):
        result = detect_ip_hostname("http://1.2.3.4/login")
        assert result is not None
        assert result.type == "ip_hostname"

    def test_punycode_type_id(self):
        result = detect_punycode_and_lookalike("xn--pypal-4ve.com")
        assert result is not None
        assert result.type == "punycode_homoglyph"

    def test_misleading_subdomain_type_id(self):
        items = detect_misleading_subdomains("https://paypal.evil.com/login")
        assert any(i.type == "misleading_subdomain" for i in items)

    def test_url_excessive_length_type_id(self):
        items = detect_url_structure_anomalies("https://x.com/" + "a" * 200)
        assert any(i.type == "url_excessive_length" for i in items)

    def test_at_symbol_redirect_type_id(self):
        items = detect_url_structure_anomalies("https://a.com@b.com/")
        assert any(i.type == "at_symbol_redirect" for i in items)

    def test_excessive_hyphens_type_id(self):
        items = detect_url_structure_anomalies("https://a-b-c-d.com/path")
        assert any(i.type == "excessive_hyphens" for i in items)

    def test_deep_nesting_type_id(self):
        items = detect_url_structure_anomalies("https://a.b.c.d.example.com/")
        assert any(i.type == "deep_subdomain_nesting" for i in items)

    def test_urgency_type_id(self):
        items = detect_urgency_and_credential_language("Your account has been suspended.")
        assert any(i.type == "urgency_language" for i in items)

    def test_credential_type_id(self):
        items = detect_urgency_and_credential_language("Please verify your password.")
        assert any(i.type == "credential_harvesting_language" for i in items)

    def test_urgency_and_credential_explanations_do_not_interpolate_raw_matches(self):
        """Privacy test: explanations must be generic and never contain exact matched strings."""
        urgent_phrase = "your account has been disabled"
        cred_phrase = "enter your social security number"
        body_text = f"Warning: {urgent_phrase} immediately! Please {cred_phrase} now."

        items = detect_urgency_and_credential_language(body_text)
        assert len(items) == 2
        for item in items:
            assert urgent_phrase not in item.explanation
            assert cred_phrase not in item.explanation
            assert "social security" not in item.explanation
            assert "disabled" not in item.explanation
            assert item.explanation in (
                "The text contains urgency or coercive language typical of social-engineering tactics designed to pressure immediate action.",
                "The text explicitly solicits sensitive credentials (such as passwords, payment details, or personal identity information) outside of a standard secure workflow.",
            )

    # -----------------------------------------------------------------------
    # Deduplication and Risk Inflation Tests
    # -----------------------------------------------------------------------

    def test_multiple_long_urls_consolidate_into_single_evidence_item(self):
        """Multiple long URLs in an email must produce a single consolidated
        url_excessive_length EvidenceItem that notes the count of affected links
        and longest length, without storing raw URLs or query parameters."""
        engine = DeterministicHeuristicsEngine()
        long_urls = [
            f"https://www.meetup.com/events/nyc-tech/rsvp?token=SECRET_TOKEN_{i}_xyz1234567890&user=usr_abc{i}&tracking=utm_email_meetup_campaign_2026_notification_reminder"
            for i in range(5)
        ]
        for u in long_urls:
            assert len(u) > 100

        evidence = engine.analyze_email(
            sender="reminders@meetup.com",
            subject="Upcoming meetup reminder",
            body_text="Here are details for your upcoming meetups.",
            links=long_urls,
        )

        length_items = [e for e in evidence if e.type == "url_excessive_length"]
        assert len(length_items) == 1, (
            f"Expected exactly 1 consolidated url_excessive_length item, got {len(length_items)}"
        )
        item = length_items[0]
        assert item.severity == "low"
        assert "5 links in this email exceed 100 characters in length" in item.explanation
        assert "longest is" in item.explanation

        # Privacy check: Ensure no token, username, or raw URL is in the explanation
        for i in range(5):
            assert f"SECRET_TOKEN_{i}" not in item.explanation
            assert f"usr_abc{i}" not in item.explanation
        assert "https://" not in item.explanation

    def test_single_long_url_in_email_preserves_standalone_explanation(self):
        """A single long URL in an email preserves the standalone explanation format."""
        engine = DeterministicHeuristicsEngine()
        single_long_url = "https://www.example.com/very/long/path/with/lots/of/padding/segments/to/obscure/the/real/target/destination/here?token=12345"
        assert len(single_long_url) > 100

        evidence = engine.analyze_email(
            sender="newsletter@example.com",
            subject="Digest",
            body_text="Read more.",
            links=[single_long_url],
        )

        length_items = [e for e in evidence if e.type == "url_excessive_length"]
        assert len(length_items) == 1
        assert "The URL is" in length_items[0].explanation
        assert str(len(single_long_url)) in length_items[0].explanation

    def test_ten_urls_same_heuristic_do_not_produce_higher_score_than_one(self):
        """Ten URLs triggering the same heuristic (url_excessive_length) must produce
        the exact same risk score (25) as a single URL triggering that heuristic.
        Repeated instances of the same heuristic rule code must not inflate the score to 45."""
        from backend.app.detection.orchestrator import RealDetectionOrchestrator
        from backend.app.schemas.scan import EvidenceItem

        orch = RealDetectionOrchestrator()

        single_item = [
            EvidenceItem(
                type="url_excessive_length",
                source="heuristics",
                severity="low",
                explanation="1 link exceeds 100 characters in length.",
            )
        ]
        score_single = orch._heuristic_score(single_item)
        assert score_single == 25

        ten_items = [
            EvidenceItem(
                type="url_excessive_length",
                source="heuristics",
                severity="low",
                explanation=f"Link {i} exceeds 100 characters in length.",
            )
            for i in range(10)
        ]
        score_ten = orch._heuristic_score(ten_items)
        assert score_ten == 25, (
            f"10 URLs with url_excessive_length must score 25 (same as 1), got {score_ten}"
        )

    def test_independent_heuristic_categories_still_contribute_independently(self):
        """When multiple distinct heuristic rule codes are present, each independent
        category beyond the first contributes 5 bonus points, even if one category
        has multiple instances."""
        from backend.app.detection.orchestrator import RealDetectionOrchestrator
        from backend.app.schemas.scan import EvidenceItem

        orch = RealDetectionOrchestrator()

        # 10 long URLs + 1 deep nesting URL -> 2 distinct categories (both low severity)
        # Base: 25, bonus: 1 * 5 = 5 -> total 30
        mixed_items = [
            EvidenceItem(
                type="url_excessive_length",
                source="heuristics",
                severity="low",
                explanation=f"Long URL {i}",
            )
            for i in range(10)
        ] + [
            EvidenceItem(
                type="deep_subdomain_nesting",
                source="heuristics",
                severity="low",
                explanation="Deep subdomain nesting",
            )
        ]

        score = orch._heuristic_score(mixed_items)
        assert score == 30, f"Expected score 30 for 2 distinct categories, got {score}"

        # Add 3rd distinct category: excessive_hyphens -> total 35
        mixed_items.append(
            EvidenceItem(
                type="excessive_hyphens",
                source="heuristics",
                severity="low",
                explanation="Excessive hyphens",
            )
        )
        score_three = orch._heuristic_score(mixed_items)
        assert score_three == 35, f"Expected score 35 for 3 distinct categories, got {score_three}"

    def test_high_confidence_phishing_indicator_retains_severity_and_scoring(self):
        """High-confidence phishing indicators (e.g. misleading_subdomain, severity='high')
        retain their full scoring weight (75 base) and reach phishing threshold (>= 70)
        even when multiple long URLs are also present."""
        from backend.app.detection.orchestrator import RealDetectionOrchestrator
        from backend.app.schemas.scan import EvidenceItem

        orch = RealDetectionOrchestrator()

        items = [
            EvidenceItem(
                type="url_excessive_length",
                source="heuristics",
                severity="low",
                explanation=f"Long URL {i}",
            )
            for i in range(5)
        ] + [
            EvidenceItem(
                type="misleading_subdomain",
                source="heuristics",
                severity="high",
                explanation="Subdomain impersonates PayPal on an unrelated domain.",
            )
        ]

        score = orch._heuristic_score(items)
        # High base = 75, plus 1 additional category (url_excessive_length) * 5 = 80
        assert score == 80
        classification = orch._classification_for_score(score, has_evidence=True)
        assert classification == "phishing"
