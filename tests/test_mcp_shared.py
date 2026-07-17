"""The MCP server's shared error-shaping layer: ``_safe_error`` + ``tool_errors``.

Agent-facing tools must never leak an internal traceback: known/teaching
exceptions pass through sanitized, everything else collapses to a generic
type-name line. The ``tool_errors`` wrapper renders that into the caller's
requested shape (dict / list / str) and always appends the doctor hint.
"""

from __future__ import annotations

import pytest

from mcp_server import _shared

pytestmark = pytest.mark.unit


def test_safe_error_passes_through_known_exceptions():
    msg = _shared._safe_error(ValueError("bad framework 'x'"), "coverage_summary")
    assert "bad framework" in msg  # teaching message preserved

    from compliance_aiops.connection import ComplianceError

    msg2 = _shared._safe_error(ComplianceError("source unreadable"), "query")
    assert "source unreadable" in msg2


def test_safe_error_masks_unknown_exceptions():
    msg = _shared._safe_error(RuntimeError("internal secret path /etc/leak"), "tool")
    assert msg == "RuntimeError: operation failed."
    assert "leak" not in msg  # internals never surfaced


def test_tool_errors_dict_shape_wraps_success_and_failure():
    @_shared.tool_errors("dict")
    def ok():
        return {"value": 1}

    @_shared.tool_errors("dict")
    def boom():
        raise ValueError("nope")

    assert ok() == {"value": 1}  # success passes straight through
    err = boom()
    assert err["error"] and "nope" in err["error"]
    assert err["hint"] == _shared._DOCTOR_HINT


def test_tool_errors_list_shape():
    @_shared.tool_errors("list")
    def boom():
        raise ValueError("listy")

    out = boom()
    assert isinstance(out, list) and out[0]["error"]
    assert "listy" in out[0]["error"]
    assert out[0]["hint"] == _shared._DOCTOR_HINT


def test_tool_errors_str_shape():
    @_shared.tool_errors("str")
    def boom():
        raise KeyError("missing")

    out = boom()
    assert isinstance(out, str)
    assert out.startswith("Error:")
    assert _shared._DOCTOR_HINT in out


def test_config_and_reader_lazy_singletons(tmp_path, monkeypatch):
    # Point the config loader at an empty tmp home so discovery is deterministic.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("COMPLIANCE_AIOPS_CONFIG", raising=False)
    monkeypatch.setattr(_shared, "_config", None)
    monkeypatch.setattr(_shared, "_reader", None)

    cfg1 = _shared._get_config()
    cfg2 = _shared._get_config()
    assert cfg1 is cfg2  # memoized

    r1 = _shared._get_reader()
    r2 = _shared._get_reader()
    assert r1 is r2


def test_config_honours_config_env_override(tmp_path, monkeypatch):
    yaml_path = tmp_path / "custom.yaml"
    yaml_path.write_text("organization: Env Org\nsources: []\n", "utf-8")
    monkeypatch.setenv("COMPLIANCE_AIOPS_CONFIG", str(yaml_path))
    monkeypatch.setattr(_shared, "_config", None)
    cfg = _shared._load()
    assert cfg.organization == "Env Org"
