"""Tests unitarios para takeovflow."""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from takeovflow import (
    _clean_domain,
    is_valid_domain,
    deduplicate_takeovers,
    filter_by_severity,
    _SEVERITY_ORDER,
)


# ------------------------------------------------------------------ #
# _clean_domain
# ------------------------------------------------------------------ #

class TestCleanDomain:
    def test_strips_https(self):
        assert _clean_domain("https://example.com") == "example.com"

    def test_strips_http(self):
        assert _clean_domain("http://example.com") == "example.com"

    def test_strips_trailing_slash(self):
        assert _clean_domain("https://example.com/") == "example.com"

    def test_strips_path(self):
        assert _clean_domain("https://example.com/some/path") == "example.com"

    def test_strips_port(self):
        assert _clean_domain("example.com:8080") == "example.com"

    def test_strips_port_with_scheme(self):
        assert _clean_domain("https://example.com:443/path") == "example.com"

    def test_lowercases(self):
        assert _clean_domain("EXAMPLE.COM") == "example.com"

    def test_plain_domain(self):
        assert _clean_domain("sub.example.com") == "sub.example.com"

    def test_strips_whitespace(self):
        assert _clean_domain("  example.com  ") == "example.com"


# ------------------------------------------------------------------ #
# is_valid_domain
# ------------------------------------------------------------------ #

class TestIsValidDomain:
    def test_simple_domain(self):
        assert is_valid_domain("example.com")

    def test_subdomain(self):
        assert is_valid_domain("sub.example.com")

    def test_deep_subdomain(self):
        assert is_valid_domain("a.b.c.example.com")

    def test_with_hyphen(self):
        assert is_valid_domain("my-app.example.com")

    def test_invalid_no_tld(self):
        assert not is_valid_domain("example")

    def test_invalid_with_scheme(self):
        assert not is_valid_domain("https://example.com")

    def test_invalid_with_port(self):
        assert not is_valid_domain("example.com:8080")

    def test_invalid_with_path(self):
        assert not is_valid_domain("example.com/path")

    def test_invalid_empty(self):
        assert not is_valid_domain("")

    def test_invalid_ip(self):
        assert not is_valid_domain("192.168.1.1")

    def test_invalid_starts_with_dot(self):
        assert not is_valid_domain(".example.com")


# ------------------------------------------------------------------ #
# deduplicate_takeovers
# ------------------------------------------------------------------ #

class TestDeduplicateTakeovers:
    def test_removes_exact_duplicates(self):
        findings = [
            {"source": "cname-pattern", "subdomain": "sub.example.com"},
            {"source": "cname-pattern", "subdomain": "sub.example.com"},
        ]
        result = deduplicate_takeovers(findings)
        assert len(result) == 1

    def test_keeps_different_sources(self):
        findings = [
            {"source": "cname-pattern",   "subdomain": "sub.example.com"},
            {"source": "http-fingerprint", "subdomain": "sub.example.com"},
        ]
        result = deduplicate_takeovers(findings)
        assert len(result) == 2

    def test_keeps_different_subdomains(self):
        findings = [
            {"source": "cname-pattern", "subdomain": "sub1.example.com"},
            {"source": "cname-pattern", "subdomain": "sub2.example.com"},
        ]
        result = deduplicate_takeovers(findings)
        assert len(result) == 2

    def test_empty_list(self):
        assert deduplicate_takeovers([]) == []

    def test_raw_fallback(self):
        findings = [
            {"source": "subjack", "raw": "sub.example.com is vulnerable"},
            {"source": "subjack", "raw": "sub.example.com is vulnerable"},
        ]
        result = deduplicate_takeovers(findings)
        assert len(result) == 1


# ------------------------------------------------------------------ #
# filter_by_severity
# ------------------------------------------------------------------ #

class TestFilterBySeverity:
    def _make(self, sev: str):
        return {"source": "test", "severity": sev, "subdomain": "x.example.com"}

    def test_filter_high_only(self):
        findings = [self._make("HIGH"), self._make("MEDIUM"), self._make("LOW"), self._make("INFO")]
        result = filter_by_severity(findings, "HIGH")
        assert all(f["severity"] == "HIGH" for f in result)
        assert len(result) == 1

    def test_filter_medium_and_above(self):
        findings = [self._make("HIGH"), self._make("MEDIUM"), self._make("LOW"), self._make("INFO")]
        result = filter_by_severity(findings, "MEDIUM")
        sevs = {f["severity"] for f in result}
        assert sevs == {"HIGH", "MEDIUM"}

    def test_filter_info_returns_all(self):
        findings = [self._make("HIGH"), self._make("MEDIUM"), self._make("LOW"), self._make("INFO")]
        result = filter_by_severity(findings, "INFO")
        assert len(result) == 4

    def test_empty(self):
        assert filter_by_severity([], "HIGH") == []

    def test_unknown_severity_defaults_to_info(self):
        findings = [{"source": "test", "severity": "UNKNOWN", "subdomain": "x.com"}]
        result = filter_by_severity(findings, "INFO")
        assert len(result) == 1
