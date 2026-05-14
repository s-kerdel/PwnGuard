"""Parse the AI's JSON response into an ``AuditResult``.

The parser is intentionally forgiving: small models routinely emit
slightly-malformed JSON (unescaped backslashes, raw newlines in
strings, nested unescaped quotes). We try plain ``json.loads`` first
and fall through a three-stage repair chain before giving up.
"""

import json
import re
from typing import Optional

from pwnguard.constants import SEVERITY_ORDER
from pwnguard.models import AuditResult, Finding, Observation
from pwnguard.security import _sanitize


def _escape_control_chars_in_strings(json_text: str) -> str:
    """Escape literal newline / CR / tab characters that appear INSIDE
    JSON string values.

    JSON forbids raw control characters inside string literals, but
    smaller models routinely emit them - typically when a long
    ``description`` or ``fix_example`` value wraps to a second line.
    This helper walks the text tracking string-vs-not state and
    converts the offending raw bytes to their escape forms (``\\n``,
    ``\\r``, ``\\t``) so a retry of ``json.loads`` succeeds.

    Whitespace OUTSIDE strings (the indentation between keys) is left
    alone - JSON allows raw newlines as whitespace there.
    """
    out = []
    in_string = False
    escape_next = False
    for ch in json_text:
        if escape_next:
            out.append(ch)
            escape_next = False
            continue
        if ch == "\\":
            out.append(ch)
            escape_next = True
            continue
        if ch == '"':
            in_string = not in_string
            out.append(ch)
            continue
        if in_string:
            if ch == "\n":
                out.append("\\n")
                continue
            if ch == "\r":
                out.append("\\r")
                continue
            if ch == "\t":
                out.append("\\t")
                continue
        out.append(ch)
    return "".join(out)


def _escape_unescaped_inner_quotes(json_text: str) -> str:
    """Escape ``"`` characters that appear inside JSON string values.

    Common small-model failure: ``fix_example`` contains code like
    ``cur.execute("SELECT ...")``, which makes the JSON look like
    ``"fix_example": "cur.execute("SELECT ...")"`` - four quotes in
    the value, only two of which are meant to be JSON delimiters.

    Walks the text in alternating in-string / out-of-string state.
    When a ``"`` is encountered inside a string, looks ahead past any
    trailing whitespace: if the next non-whitespace char is a JSON
    structural token (``,`` ``}`` ``]`` ``:``) or end-of-input, it's
    the real closer; otherwise it's a nested unescaped quote and gets
    escaped so the closer-matching can continue past it.

    Limitation: values containing patterns like ``"a", "b"`` (multiple
    quoted substrings on the same line) will be misclassified - the
    walker will treat the first inner closing quote as the real
    closer. Acceptable trade-off: rare in code snippets, common in
    the cur.execute / db.prepare / shell strings that the prompt now
    asks the model to single-quote anyway.
    """
    out = []
    in_string = False
    escape_next = False
    n = len(json_text)
    for i, ch in enumerate(json_text):
        if escape_next:
            out.append(ch)
            escape_next = False
            continue
        if ch == "\\":
            out.append(ch)
            escape_next = True
            continue
        if ch != '"':
            out.append(ch)
            continue
        if not in_string:
            out.append(ch)
            in_string = True
            continue
        # We're inside a string and found a `"`. Look ahead past any
        # whitespace (including newlines - by this stage raw newlines
        # inside string values have already been escaped by
        # _escape_control_chars_in_strings, so any \n we see here is
        # between JSON tokens, not inside one) to decide whether it's
        # the real closer or a nested unescaped quote.
        j = i + 1
        while j < n and json_text[j] in " \t\n\r":
            j += 1
        if j >= n or json_text[j] in ",}]:":
            out.append(ch)
            in_string = False
        else:
            out.append("\\")
            out.append(ch)
    return "".join(out)


def _normalize_anchor(raw) -> Optional[str]:
    """Coerce a model-supplied anchor field into the canonical bare-token form.

    Accepts ``"a8"``, ``"[a8]"`` (model echoed the diff prefix), ``8`` /
    ``"8"`` (model dropped the letter prefix), and rejects everything
    else as None. Whitespace around the value is stripped.
    """
    if raw is None:
        return None
    s = str(raw).strip()
    if not s:
        return None
    # Strip enclosing brackets if the model echoed the diff prefix literally.
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1].strip()
    # Bare integer fallback - model dropped the letter prefix.
    if s.isdigit():
        s = f"a{s}"
    # Must match the [a-z]+\d+ shape our tagger emits.
    if not re.match(r"^[a-z]+\d+$", s):
        return None
    return s


def parse_response(response: str) -> AuditResult:
    """Parse AI response JSON into AuditResult."""
    result = AuditResult()

    cleaned = response.strip()

    # Strip markdown fences if the model wrapped its JSON in ``` ... ```
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
    cleaned = re.sub(r"\s*```$", "", cleaned)

    # Extract the outermost JSON object (handles preamble/postamble text).
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if not match:
        # Sanitize the raw excerpt before embedding it in the error so
        # a malformed AI response can't inject ANSI escapes via the
        # printed error message.
        result.error = (
            f"No JSON object in AI response.\n"
            f"Raw response:\n{_sanitize(response[:500])}"
        )
        return result

    raw_json = match.group(0)
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        # Three-stage fix-then-retry path for common small-model JSON sins:
        #   1. Unescaped backslashes inside string values (esc \ -> \\).
        #   2. Literal newlines / CRs / tabs inside string values
        #      (these are illegal in JSON; small models emit them when
        #      a long `description` or `fix_example` wraps to a new line).
        #   3. Unescaped double quotes inside string values - typically
        #      when fix_example contains code like cur.execute("...").
        fixed = re.sub(r'\\(?!["\\/bfnrtu])', r"\\\\", raw_json)
        try:
            data = json.loads(fixed)
        except json.JSONDecodeError:
            fixed2 = _escape_control_chars_in_strings(fixed)
            try:
                data = json.loads(fixed2)
            except json.JSONDecodeError:
                try:
                    data = json.loads(_escape_unescaped_inner_quotes(fixed2))
                except json.JSONDecodeError as e:
                    # Sanitize the raw excerpt before embedding it in the
                    # error; see the comment above for the injection rationale.
                    result.error = (
                        f"Failed to parse AI response: {e}\n"
                        f"Raw response:\n{_sanitize(response[:500])}"
                    )
                    return result

    # Schema-mismatch guard: the response parsed as valid JSON but
    # doesn't have a ``findings`` key. Common when a smaller / safety-
    # tuned model treats the prompt as chat - e.g. responds with
    # ``{"response": "I can't help with that"}`` or
    # ``{"response": "The code looks fine"}``. Without this check the
    # missing-key path silently degrades to ``findings=[]`` and the
    # downstream UI shows a clean repo, hiding the fact that no real
    # audit happened. Treat as an error so the caller surfaces it.
    if not isinstance(data, dict) or "findings" not in data:
        result.error = (
            "AI response is valid JSON but lacks a 'findings' field "
            "(model likely treated the prompt as chat instead of an "
            "audit task).\n"
            f"Raw response:\n{_sanitize(response[:500])}"
        )
        return result

    for item in data.get("findings", []):
        # Validate severity / confidence; fall back to safe defaults.
        severity = item.get("severity", "INFO").upper()
        if severity not in SEVERITY_ORDER:
            severity = "INFO"
        confidence = item.get("confidence", "high").lower()
        if confidence not in ("high", "medium", "low"):
            confidence = "high"
        # Sanitize every AI-controlled string field so a crafted diff can't
        # inject terminal escape sequences via the model.
        raw_cwe = item.get("cwe")
        raw_fix_example = item.get("fix_example")
        # Accept both the bare token ("a8") and the bracketed form
        # ("[a8]") in case the model echoed the diff prefix literally.
        raw_anchor = item.get("anchor")
        anchor = _normalize_anchor(raw_anchor)
        result.findings.append(Finding(
            severity=severity,
            title=_sanitize(item.get("title", "Untitled finding")),
            # file/line are placeholders here; resolve_anchors will
            # rewrite them from the anchor table. For the file-level
            # carve-out the model supplies "file" directly and the
            # anchor stays None - resolution leaves it alone.
            file=_sanitize(item.get("file", "")),
            line=None,
            description=_sanitize(item.get("description", "")),
            recommendation=_sanitize(item.get("recommendation", "")),
            cwe=_sanitize(raw_cwe) if raw_cwe else None,
            confidence=confidence,
            fix_example=_sanitize(raw_fix_example) if raw_fix_example else None,
            anchor=anchor,
        ))

    # Observations (opt-in via --show-observations). Best-effort parse:
    # missing field, empty list, or non-dict items all silently degrade
    # to "no observation added" rather than failing the whole scan.
    for item in (data.get("observations") or []):
        if not isinstance(item, dict):
            continue
        pattern = _sanitize(item.get("pattern", "")).strip()
        note = _sanitize(item.get("note", "")).strip()
        if not pattern and not note:
            continue
        # Cap at 5 to enforce the prompt's stated ceiling on the parse
        # side too - a runaway model can't flood the output.
        if len(result.observations) >= 5:
            break
        raw_anchor = item.get("anchor")
        anchor = _normalize_anchor(raw_anchor)
        result.observations.append(Observation(
            pattern=pattern or "(unspecified)",
            file=_sanitize(item.get("file", "")).strip(),
            line=None,
            note=note,
            anchor=anchor,
        ))
    return result
