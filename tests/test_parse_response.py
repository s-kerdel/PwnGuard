"""Tests for the JSON parse + repair pipeline.

Covers the four-stage retry chain in parse_response:
    1. Direct json.loads
    2. Backslash-escape repair
    3. Control-char-escape repair (raw newlines etc. inside strings)
    4. Inner-quote escape (added in v0.1.2)
"""
import json

import pytest

import audit


def _finding_dict(anchor="a1", **overrides):
    base = {
        "severity": "HIGH",
        "confidence": "high",
        "anchor": anchor,
        "title": "x",
        "description": "d",
        "recommendation": "r",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_simple_valid_response():
    raw = json.dumps({"findings": [_finding_dict()]})
    result = audit.parse_response(raw)
    assert result.error is None
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.severity == "HIGH"
    assert f.anchor == "a1"


def test_empty_findings_response():
    result = audit.parse_response('{"findings": []}')
    assert result.findings == []
    assert result.error is None


def test_markdown_fence_is_stripped():
    result = audit.parse_response('```json\n{"findings": []}\n```')
    assert result.findings == []
    assert result.error is None


def test_preamble_text_is_ignored():
    raw = ('Sure, here are the findings:\n\n'
           '{"findings": []}\n\nLet me know if you need more.')
    result = audit.parse_response(raw)
    assert result.findings == []


def test_invalid_severity_defaults_to_info():
    raw = json.dumps({"findings": [_finding_dict(severity="GIGA")]})
    result = audit.parse_response(raw)
    assert result.findings[0].severity == "INFO"


def test_invalid_confidence_defaults_to_high():
    raw = json.dumps({"findings": [_finding_dict(confidence="extreme")]})
    result = audit.parse_response(raw)
    assert result.findings[0].confidence == "high"


# ---------------------------------------------------------------------------
# Anchor handling at parse time
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("anchor_in, anchor_out", [
    ("a8", "a8"),
    ("[a8]", "a8"),
    (8, "a8"),
    ("8", "a8"),
])
def test_anchor_normalised_during_parse(anchor_in, anchor_out):
    raw = json.dumps({"findings": [_finding_dict(anchor=anchor_in)]})
    result = audit.parse_response(raw)
    assert result.findings[0].anchor == anchor_out


def test_missing_anchor_left_as_none():
    item = _finding_dict()
    item.pop("anchor")
    raw = json.dumps({"findings": [item]})
    result = audit.parse_response(raw)
    assert result.findings[0].anchor is None


def test_file_supplied_for_file_level_finding():
    item = _finding_dict(file="config.yaml")
    item.pop("anchor")
    raw = json.dumps({"findings": [item]})
    result = audit.parse_response(raw)
    assert result.findings[0].file == "config.yaml"


# ---------------------------------------------------------------------------
# Error path
# ---------------------------------------------------------------------------

def test_completely_invalid_input_returns_error():
    result = audit.parse_response("this is not json at all")
    assert result.error is not None
    assert result.findings == []


def test_no_json_object_in_response_returns_error():
    result = audit.parse_response("just some prose, nothing braced")
    assert result.error is not None


def test_off_schema_json_response_is_caught_as_error():
    """Smaller models sometimes treat the prompt as chat and emit
    `{"response": "I can't help"}` instead of the findings schema.
    Without explicit detection this would parse as ``findings=[]`` and
    look like a clean audit. The parser must surface it as an error
    so the monitor doesn't silently report falsely-clean repos."""
    refusal = '{"response": "I\'m sorry, but I can\'t assist with that."}'
    result = audit.parse_response(refusal)
    assert result.error is not None
    assert "findings" in result.error.lower()
    assert result.findings == []


def test_off_schema_json_with_prose_response_caught():
    """Verbose paraphrase responses must also trigger the schema
    guard, not just short refusals."""
    prose = (
        '{"response": "The provided code review does not contain any '
        'security vulnerabilities or issues."}'
    )
    result = audit.parse_response(prose)
    assert result.error is not None
    assert result.findings == []


# ---------------------------------------------------------------------------
# JSON repair pipeline
# ---------------------------------------------------------------------------

def test_lone_backslash_in_value_is_repaired():
    raw = (
        '{"findings": [{"severity": "HIGH", "anchor": "a1", '
        '"title": "x", "description": "windows path C:\\Users", '
        '"recommendation": "r"}]}'
    )
    result = audit.parse_response(raw)
    assert result.error is None
    assert len(result.findings) == 1


def test_raw_newline_in_value_is_repaired():
    raw = (
        '{"findings": [{"severity": "HIGH", "anchor": "a1", '
        '"title": "x", "description": "line 1\nline 2", '
        '"recommendation": "r"}]}'
    )
    result = audit.parse_response(raw)
    assert result.error is None


def test_nested_unescaped_quotes_repaired():
    """The exact user-reported failure case from the v0.1.2 dev cycle."""
    raw = (
        '{"findings": [{"severity": "HIGH", "confidence": "high", '
        '"anchor": "a34", "title": "sql injection in get_user", '
        '"description": "The SQL query is not parameterized.", '
        '"recommendation": "Use parameterized queries.", '
        '"fix_example": "cur.execute("SELECT id, name, email FROM users WHERE id = ?")"}]}'
    )
    result = audit.parse_response(raw)
    assert result.error is None
    assert len(result.findings) == 1
    assert "SELECT" in result.findings[0].fix_example


# ---------------------------------------------------------------------------
# _escape_unescaped_inner_quotes walker (stage 4 of the repair chain)
# ---------------------------------------------------------------------------

def test_walker_leaves_valid_json_unchanged():
    s = '{"a": "hello, world", "b": "value"}'
    assert audit._escape_unescaped_inner_quotes(s) == s


def test_walker_leaves_apostrophes_unchanged():
    s = '{"a": "value with \' apostrophe"}'
    assert audit._escape_unescaped_inner_quotes(s) == s


def test_walker_repairs_simple_nested_quote():
    bad = '{"fix": "cur.execute("SELECT 1")"}'
    data = json.loads(audit._escape_unescaped_inner_quotes(bad))
    assert data["fix"] == 'cur.execute("SELECT 1")'


def test_walker_repairs_user_payload():
    bad = (
        '{"fix_example": "cur.execute('
        '"SELECT id, name, email FROM users WHERE id = ?"'
        ')"}'
    )
    data = json.loads(audit._escape_unescaped_inner_quotes(bad))
    assert "SELECT" in data["fix_example"]


# ---------------------------------------------------------------------------
# Observations
# ---------------------------------------------------------------------------

def test_observation_anchor_is_parsed():
    raw = json.dumps({
        "findings": [],
        "observations": [{
            "pattern": "parameterised query",
            "anchor": "a5",
            "note": "user_id bound via PDO",
        }],
    })
    result = audit.parse_response(raw)
    assert len(result.observations) == 1
    o = result.observations[0]
    assert o.pattern == "parameterised query"
    assert o.anchor == "a5"


def test_observations_capped_at_five():
    raw = json.dumps({
        "findings": [],
        "observations": [
            {"pattern": f"p{i}", "note": "n"} for i in range(10)
        ],
    })
    result = audit.parse_response(raw)
    assert len(result.observations) == 5
