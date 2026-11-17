"""GUG-542: the extractors share one model profile and no retired default model."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXTRACTORS = ("bank", "personal", "gov")


def _worker_file(service: str, relative: str) -> Path:
    return ROOT / "backend" / "workers" / f"scanalyze-{service}-worker" / "src" / f"{service}_worker" / relative


def test_extractors_keep_identical_model_profiles() -> None:
    copies = {_worker_file(service, "model_profile.py").read_text(encoding="utf-8") for service in EXTRACTORS}
    assert len(copies) == 1, "model_profile.py drifted between the extractors"


def test_no_extractor_defaults_to_claude_3_haiku() -> None:
    for service in EXTRACTORS:
        source = _worker_file(service, "processors/extract.py").read_text(encoding="utf-8")
        assert "claude-3-haiku" not in source, f"{service} still defaults to a retired model"
