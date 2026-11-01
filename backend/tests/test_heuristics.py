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
        assert_evidence_item(item, expected_type="url_excessive_length", expected_severity="medium")

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
        assert_evidence_item(item, expected_type="deep_subdomain_nesting", expected_severity="medium")

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
