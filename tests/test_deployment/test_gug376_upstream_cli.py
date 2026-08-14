"""Custody and sanitization tests for the offline GUG-376 CLI."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

from tooling.platform_authority_gug365_upstream_prerequisites import canonical_digest


ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "scripts/deployment/platform-authority-gug365-upstream.py"
D1 = "sha256:" + "1" * 64
D2 = "sha256:" + "2" * 64


def _artifact() -> dict[str, object]:
    return json.loads(
        (
            ROOT
            / "fixtures/valid/"
            "platform-authority-gug365-upstream-final-handoff-v1-synthetic.json"
        ).read_text(encoding="utf-8")
    )


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "owner-private"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    return root


def _run(root: Path, relative: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(CLI),
            "--private-root",
            str(root),
            "--input",
            relative,
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_cli_validates_private_artifact_and_prints_digest_only(tmp_path: Path) -> None:
    root = _root(tmp_path)
    artifact = root / "stop-checkpoint.json"
    artifact.write_text(json.dumps(_artifact()), encoding="utf-8")
    artifact.chmod(0o600)

    result = _run(root, artifact.name)

    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output["status"] == "STOP_UPSTREAM_SOURCE_CONTRACT_GAP"
    assert output["aws_calls_performed"] == 0
    assert output["aws_mutations"] == 0
    assert output["provider_evidence"] == "NOT_PROVEN"
    assert output["runtime_pin"] == "NOT_PROVEN"
    assert output["private_root_authority"] == "NOT_PROVEN"
    assert str(root) not in result.stdout


def test_cli_rejects_permissive_file_without_leaking_path(tmp_path: Path) -> None:
    root = _root(tmp_path)
    artifact = root / "stop-checkpoint.json"
    artifact.write_text(json.dumps(_artifact()), encoding="utf-8")
    artifact.chmod(0o644)

    result = _run(root, artifact.name)

    assert result.returncode == 2
    assert json.loads(result.stderr) == {
        "status": "BLOCKED",
        "code": "PRIVATE_INPUT_CUSTODY_INVALID",
    }
    assert str(root) not in result.stderr


def test_cli_rejects_symlink_and_duplicate_json_keys(tmp_path: Path) -> None:
    root = _root(tmp_path)
    target = root / "target.json"
    target.write_text(json.dumps(_artifact()), encoding="utf-8")
    target.chmod(0o600)
    link = root / "link.json"
    link.symlink_to(target)

    symlink_result = _run(root, link.name)
    assert symlink_result.returncode == 2
    assert json.loads(symlink_result.stderr)["code"] == "PRIVATE_INPUT_UNAVAILABLE"

    duplicate = root / "duplicate.json"
    duplicate.write_text('{"record_type":"one","record_type":"two"}', encoding="utf-8")
    duplicate.chmod(0o600)
    duplicate_result = _run(root, duplicate.name)
    assert duplicate_result.returncode == 2
    assert json.loads(duplicate_result.stderr)["code"] == "PRIVATE_JSON_DUPLICATE_KEY"


def test_cli_rejects_relative_root_before_read(tmp_path: Path) -> None:
    result = _run(Path("relative-private-root"), "artifact.json")
    assert result.returncode == 2
    assert json.loads(result.stderr)["code"] == "PRIVATE_ROOT_NOT_ABSOLUTE"


def test_cli_rejects_repository_scaffolding_as_public_proof(tmp_path: Path) -> None:
    root = _root(tmp_path)
    for name in ("owner-decisions", "inventory"):
        artifact = json.loads(
            (
                ROOT
                / "fixtures/valid/"
                f"platform-authority-gug365-upstream-{name}-v1-synthetic.json"
            ).read_text(encoding="utf-8")
        )
        path = root / f"{name}.json"
        path.write_text(json.dumps(artifact), encoding="utf-8")
        path.chmod(0o600)

        result = _run(root, path.name)

        assert result.returncode == 2
        assert json.loads(result.stderr) == {
            "status": "BLOCKED",
            "code": "PRIVATE_ARTIFACT_RECORD_TYPE_UNSUPPORTED",
        }

    forged_slot = root / "forged-provider-slot.json"
    forged_slot.write_text(
        json.dumps(
            {
                "record_type": (
                    "scanalyze.platform_authority."
                    "gug365_upstream_provider_slot_binding.v1"
                ),
                "provider_value_attested": True,
            }
        ),
        encoding="utf-8",
    )
    forged_slot.chmod(0o600)
    result = _run(root, forged_slot.name)
    assert result.returncode == 2
    assert json.loads(result.stderr)["code"] == (
        "PRIVATE_ARTIFACT_RECORD_TYPE_UNSUPPORTED"
    )


def test_cli_rejects_resealed_inventory_live_overclaim(tmp_path: Path) -> None:
    inventory = json.loads(
        (
            ROOT
            / "fixtures/valid/"
            "platform-authority-gug365-upstream-inventory-v1-synthetic.json"
        ).read_text(encoding="utf-8")
    )
    inventory.update(
        {
            "evidence_origin": "EXTERNALLY_ATTESTED_PROVIDER",
            "provider_transcript_verified": True,
            "provider_transcript_verification_digests": [D1, D2],
            "provider_verifier_identity_digest": D1,
            "provider_attestation_root_digest": D2,
        }
    )
    inventory["inventory_digest"] = canonical_digest(
        {
            key: value
            for key, value in inventory.items()
            if key != "inventory_digest"
        }
    )
    root = _root(tmp_path)
    artifact = root / "resealed-live-inventory.json"
    artifact.write_text(json.dumps(inventory), encoding="utf-8")
    artifact.chmod(0o600)

    result = _run(root, artifact.name)

    assert result.returncode == 2
    assert json.loads(result.stderr) == {
        "status": "BLOCKED",
        "code": "PRIVATE_ARTIFACT_RECORD_TYPE_UNSUPPORTED",
    }


def test_cli_reports_only_zero_effect_stop_handoff(tmp_path: Path) -> None:
    checkpoint = json.loads(
        (
            ROOT
            / "fixtures/valid/"
            "platform-authority-gug365-upstream-final-handoff-v1-synthetic.json"
        ).read_text(encoding="utf-8")
    )
    root = _root(tmp_path)
    artifact = root / "blocked-handoff.json"
    artifact.write_text(json.dumps(checkpoint), encoding="utf-8")
    artifact.chmod(0o600)

    result = _run(root, artifact.name)

    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output["status"] == "STOP_UPSTREAM_SOURCE_CONTRACT_GAP"
    assert output["state"] == "STOPPED_BEFORE_FIRST_AWS_WRITE"
    assert output["deployment_authorized"] is False
    assert output["aws_calls_performed"] == 0
    assert output["aws_mutations"] == 0


def test_cli_rejects_authorize_overclaim_checkpoint(tmp_path: Path) -> None:
    overclaim = json.loads(
        (
            ROOT
            / "fixtures/invalid/"
            "platform-authority-gug365-upstream-"
            "phase-authorization-v1-retry-overclaim.json"
        ).read_text(encoding="utf-8")
    )
    root = _root(tmp_path)
    artifact = root / "authorize-overclaim.json"
    artifact.write_text(json.dumps(overclaim), encoding="utf-8")
    artifact.chmod(0o600)

    result = _run(root, artifact.name)

    assert result.returncode == 2
    assert json.loads(result.stderr) == {
        "status": "BLOCKED",
        "code": "AUTHORIZATION_STOP_CHECKPOINT_INVALID",
    }
