"""Tests for the dataclass methods that decide commit pass / fail.

``AuditResult.exceeds_threshold`` is what the CLI exits on. A bug here
turns the pre-commit / CI gate into a no-op (or, worse, blocks every
commit). These tests pin the contract.
"""
import pytest

import audit


def _f(severity: str, confidence: str = "high", cwe: str = None) -> audit.Finding:
    """Build a minimal Finding for threshold / summary tests."""
    return audit.Finding(
        severity=severity, title="t", file="x", line=1,
        description="d", recommendation="r",
        confidence=confidence, cwe=cwe,
    )


# ---------------------------------------------------------------------------
# AuditResult.summary
# ---------------------------------------------------------------------------

def test_summary_empty_when_no_findings():
    result = audit.AuditResult()
    assert result.summary == {}


def test_summary_counts_findings_per_severity():
    result = audit.AuditResult()
    result.findings = [
        _f("CRITICAL"),
        _f("HIGH"), _f("HIGH"),
        _f("MEDIUM"), _f("MEDIUM"), _f("MEDIUM"),
        _f("LOW"),
    ]
    assert result.summary == {
        "CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 1,
    }


# ---------------------------------------------------------------------------
# AuditResult.blocking_findings - confidence filter
# ---------------------------------------------------------------------------

def test_blocking_findings_keeps_high_and_medium_confidence():
    result = audit.AuditResult()
    result.findings = [
        _f("HIGH", confidence="high"),
        _f("HIGH", confidence="medium"),
        _f("HIGH", confidence="low"),     # excluded
    ]
    blocking = result.blocking_findings
    assert len(blocking) == 2
    assert all(f.confidence in ("high", "medium") for f in blocking)


def test_blocking_findings_empty_when_only_low_confidence():
    result = audit.AuditResult()
    result.findings = [_f("CRITICAL", confidence="low")]
    assert result.blocking_findings == []


# ---------------------------------------------------------------------------
# AuditResult.exceeds_threshold - the actual gate
# ---------------------------------------------------------------------------

def test_threshold_exceeded_when_finding_severity_above():
    result = audit.AuditResult()
    result.findings = [_f("CRITICAL")]
    assert result.exceeds_threshold("HIGH") is True


def test_threshold_exceeded_when_finding_severity_equal():
    """`>=` semantics - a finding AT the threshold blocks."""
    result = audit.AuditResult()
    result.findings = [_f("HIGH")]
    assert result.exceeds_threshold("HIGH") is True


def test_threshold_not_exceeded_when_finding_severity_below():
    result = audit.AuditResult()
    result.findings = [_f("MEDIUM")]
    assert result.exceeds_threshold("HIGH") is False


def test_threshold_not_exceeded_when_no_findings():
    result = audit.AuditResult()
    assert result.exceeds_threshold("HIGH") is False


def test_low_confidence_findings_do_not_trip_threshold():
    """A CRITICAL/low-confidence finding does not block."""
    result = audit.AuditResult()
    result.findings = [_f("CRITICAL", confidence="low")]
    assert result.exceeds_threshold("HIGH") is False


# ---------------------------------------------------------------------------
# Finding.cwe_url - hallucination guard
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("cwe, expected", [
    ("CWE-89",  "https://cwe.mitre.org/data/definitions/89.html"),
    ("CWE-79",  "https://cwe.mitre.org/data/definitions/79.html"),
    ("CWE-1",   "https://cwe.mitre.org/data/definitions/1.html"),
    ("cwe-918", "https://cwe.mitre.org/data/definitions/918.html"),  # case-insensitive
    ("  CWE-22  ", "https://cwe.mitre.org/data/definitions/22.html"),  # whitespace ok
])
def test_cwe_url_built_for_well_formed_id(cwe, expected):
    f = _f("HIGH", cwe=cwe)
    assert f.cwe_url() == expected


@pytest.mark.parametrize("cwe", [
    None,
    "",
    "CWE-???",        # hallucinated value
    "CWE-XXX",
    "CWE89",          # missing dash
    "CWE-",           # missing digits
    "CWE-89 extra",   # trailing garbage
    "MITRE-89",       # wrong prefix
    "89",             # bare number
])
def test_cwe_url_refused_for_malformed_id(cwe):
    """Hallucinated / malformed CWE IDs must not produce a broken link target."""
    f = _f("HIGH", cwe=cwe)
    assert f.cwe_url() is None
