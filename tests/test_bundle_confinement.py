"""Path confinement for agent-supplied bundle/export output paths.

``out_path`` comes from the calling agent; it must not be able to write
artifacts outside the configured bundle directory (or, for exports, outside
the source bundle's own directory).
"""

from __future__ import annotations

import pytest


@pytest.fixture
def env(tmp_path):
    """A real-schema (empty) audit source + a config confined to tmp bundles/."""
    from compliance_aiops.config import AppConfig, AuditSource
    from compliance_aiops.connection import AuditReader
    from compliance_aiops.governance.audit import AuditEngine

    source_db = tmp_path / "source.db"
    AuditEngine(str(source_db))  # creates the real audit_log schema
    source = AuditSource(name="testsrc", path=source_db)
    reader = AuditReader([source])
    cfg = AppConfig(sources=(source,), organization="Acme",
                    bundle_dir=tmp_path / "bundles")
    return reader, cfg, tmp_path


@pytest.mark.unit
def test_generate_rejects_relative_escape(env):
    from compliance_aiops.ops import bundle as ops

    reader, cfg, _ = env
    with pytest.raises(ValueError, match="allowed output directory"):
        ops.generate_evidence_bundle(reader, cfg, "soc2", out_path="../../evil")


@pytest.mark.unit
def test_generate_rejects_absolute_path_outside_base(env):
    from compliance_aiops.ops import bundle as ops

    reader, cfg, tmp_path = env
    outside = tmp_path / "elsewhere" / "evil.json"
    with pytest.raises(ValueError, match="allowed output directory"):
        ops.generate_evidence_bundle(reader, cfg, "soc2", out_path=str(outside))


@pytest.mark.unit
def test_generate_bare_filename_lands_inside_bundle_dir(env):
    from pathlib import Path

    from compliance_aiops.ops import bundle as ops

    reader, cfg, _ = env
    result = ops.generate_evidence_bundle(reader, cfg, "soc2", out_path="mybundle.json")
    written = Path(result["bundlePath"])
    assert written.is_file()
    assert written.parent == cfg.bundle_dir.resolve()


@pytest.mark.unit
def test_export_rejects_escape_from_bundle_directory(env):
    from compliance_aiops.ops import bundle as ops

    reader, cfg, _ = env
    result = ops.generate_evidence_bundle(reader, cfg, "soc2", out_path="b.json")
    with pytest.raises(ValueError, match="allowed output directory"):
        ops.export_bundle(result["bundlePath"], fmt="markdown", out_path="../evil.md")
