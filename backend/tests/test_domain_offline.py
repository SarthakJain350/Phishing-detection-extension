"""Tests for offline-safe domain normalization and Public Suffix List behavior."""

from __future__ import annotations

import socket
import urllib.request
import pytest

from backend.app.core.domain import clean_url_or_hostname, extract_domain_info, normalize_target_reference


class TestOfflineDomainNormalization:
    """Verify that domain extraction and normalization operate strictly offline

    with complete coverage of edge cases.
    """

    def test_multi_level_public_suffixes(self):
        """Verify that multi-level ccTLDs and public suffixes are correctly partitioned."""
        # UK commercial ccTLD
        info = extract_domain_info("https://login.paypal.co.uk/signin")
        assert info.target_reference == "login.paypal.co.uk"
        assert info.registered_domain == "paypal.co.uk"
        assert info.subdomain == "login"
        assert info.suffix == "co.uk"
        assert not info.is_ip

        # Australian commercial ccTLD
        info_au = extract_domain_info("http://secure.banking.commbank.com.au:8080/")
        assert info_au.target_reference == "secure.banking.commbank.com.au"
        assert info_au.registered_domain == "commbank.com.au"
        assert info_au.subdomain == "secure.banking"
        assert info_au.suffix == "com.au"

        # Multi-level user subdomain platform (e.g. github.io)
        info_gh = extract_domain_info("https://phish-test.github.io/payload")
        assert info_gh.target_reference == "phish-test.github.io"
        assert info_gh.registered_domain == "github.io"
        assert info_gh.subdomain == "phish-test"
        assert info_gh.suffix == "io"

    def test_uppercase_input(self):
        """Verify that uppercase URLs and hostnames are normalized to lowercase."""
        info = extract_domain_info("HTTPS://LOGIN.MICROSOFT.COM/OAUTH")
        assert info.target_reference == "login.microsoft.com"
        assert info.registered_domain == "microsoft.com"
        assert info.subdomain == "login"

    def test_trailing_dots(self):
        """Verify that FQDNs with trailing dots are cleanly stripped."""
        info = extract_domain_info("https://example.com./test")
        assert info.target_reference == "example.com"
        assert info.registered_domain == "example.com"

        info_host = extract_domain_info("sub.bank.org.")
        assert info_host.target_reference == "sub.bank.org"

    def test_ports_and_credentials_stripped(self):
        """Verify that ports and authentication credentials are completely stripped."""
        info = extract_domain_info("http://admin:secret_pass@malicious-site.com:8443/login?token=abc#frag")
        assert info.target_reference == "malicious-site.com"
        assert "admin" not in info.target_reference
        assert "8443" not in info.target_reference
        assert "token" not in info.target_reference

    def test_ipv4_addresses(self):
        """Verify that IPv4 addresses are correctly detected and normalized."""
        info = extract_domain_info("http://192.168.1.1:8000/login")
        assert info.target_reference == "192.168.1.1"
        assert info.registered_domain == "192.168.1.1"
        assert info.subdomain == ""
        assert info.is_ip is True
        assert info.is_ipv4 is True
        assert info.is_ipv6 is False

        # Raw IP without scheme
        info_raw = extract_domain_info("10.0.0.1")
        assert info_raw.target_reference == "10.0.0.1"
        assert info_raw.is_ip is True
        assert info_raw.is_ipv4 is True

    def test_ipv6_addresses(self):
        """Verify that IPv6 addresses are correctly detected and normalized."""
        info = extract_domain_info("http://[::1]:8080/path")
        assert info.target_reference == "::1"
        assert info.is_ip is True
        assert info.is_ipv6 is True

    def test_punycode_and_internationalized_domains(self):
        """Verify that Punycode / IDN domains are normalized consistently."""
        # e.g. Cyrillic domain 'пример.рф' -> 'xn--e1afmkfd.xn--p1ai'
        info = extract_domain_info("http://xn--e1afmkfd.xn--p1ai/path")
        assert "xn--" in info.target_reference

    def test_malformed_urls_raise_value_error(self):
        """Verify that invalid inputs raise descriptive ValueErrors."""
        invalid_inputs = [
            "",
            "   ",
            None,
            "ftp://files.example.com",
            "javascript:alert(1)",
            "data:text/html,<html>",
            "http://",
            "http:///",
        ]
        for val in invalid_inputs:
            with pytest.raises(ValueError):
                clean_url_or_hostname(val)

    def test_runtime_network_isolation(self, monkeypatch):
        """Strictly prove that domain normalization executes without ANY network calls.

        Monkeypatches socket and urllib to fail if called.
        """
        def blocked_socket(*args, **kwargs):
            raise AssertionError("Network socket call attempted during offline domain normalization!")

        def blocked_urlopen(*args, **kwargs):
            raise AssertionError("HTTP request attempted during offline domain normalization!")

        monkeypatch.setattr(socket, "socket", blocked_socket)
        monkeypatch.setattr(urllib.request, "urlopen", blocked_urlopen)

        # Execute extraction across complex cases under blocked network
        test_cases = [
            "https://sub.domain.co.uk",
            "http://192.168.1.1:8000/path",
            "https://LOGIN.PAYPAL.COM:443/",
            "https://attacker.github.io/phish",
            "https://bbc.co.uk.",
        ]
        for url in test_cases:
            info = extract_domain_info(url)
            assert info.target_reference is not None

        ref = normalize_target_reference("https://verify.apple.com.secure-update.org/login")
        assert ref == "verify.apple.com.secure-update.org"
