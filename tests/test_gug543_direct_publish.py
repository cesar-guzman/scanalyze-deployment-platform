"""GUG-543 — owner-run publication for a direct-path deployment.

These offline checks run the publish scripts in --dry-run mode, which makes no
AWS or Docker calls, and the service-definition renderer on synthetic digests.
"""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
PUBLISH_IMAGES = REPO_ROOT / "scripts" / "deployment" / "publish-direct-release.sh"
PUBLISH_FRONTEND = REPO_ROOT / "scripts" / "deployment" / "publish-frontend.sh"
RENDERER_PATH = REPO_ROOT / "scripts" / "deployment" / "render-direct-service-definitions.py"
ROUTING = REPO_ROOT / "deployment" / "express-production-routing.json"

ACCOUNT = "123456789012"
REGION = "us-east-1"
DEPLOYMENT = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
SANITIZED = "dep-01arz3ndektsv4rrffq69g5fav"
BASE = f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/{SANITIZED}/scanalyze/base@sha256:{'a' * 64}"
SERVICES = (
    "ingest-api",
    "ocr-worker",
    "postprocess-worker",
    "classifier-worker",
    "bank-worker",
    "personal-worker",
    "gov-worker",
)


def _renderer():
    spec = importlib.util.spec_from_file_location("render_direct_service_definitions", RENDERER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _release(**overrides) -> dict:
    release = {
        "schema_version": "scanalyze.direct-release-images.v1",
        "account_id": ACCOUNT,
        "region": REGION,
        "deployment_id": DEPLOYMENT,
        "tag": "pilot-synthetic",
        "revision": "0" * 40,
        "images": {service: f"sha256:{format(index, 'x') * 64}" for index, service in enumerate(SERVICES, start=1)},
    }
    release.update(overrides)
    return release


def _run(script: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["bash", str(script), *args], capture_output=True, text=True, check=False)


def _image_args(tmp_path: Path, **overrides: str) -> list[str]:
    values = {
        "--account-id": ACCOUNT,
        "--region": REGION,
        "--deployment-id": DEPLOYMENT,
        "--base-image": BASE,
        "--tag": "pilot-synthetic",
        "--output": str(tmp_path / "release-images.json"),
    }
    values.update(overrides)
    return [item for pair in values.items() for item in pair]


def test_image_dry_run_prepares_wheelhouses_then_pushes_every_service(tmp_path: Path) -> None:
    result = _run(PUBLISH_IMAGES, *_image_args(tmp_path), "--dry-run")
    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    assert "prepare-ocr-wheelhouse.sh" in lines[0]
    assert "prepare-classifier-wheelhouse.sh" in lines[1]
    push = lines[2]
    for expected in ("build-push.sh", "--all", "--push", "--write-ssm", f"--ecr-prefix {SANITIZED}/scanalyze", f"--deployment-id {DEPLOYMENT}"):
        assert expected in push
    for service in SERVICES:
        assert any(f"{SANITIZED}/scanalyze/{service}" in line for line in lines[3:])
    assert not (tmp_path / "release-images.json").exists()


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"--account-id": "000000000000"}, "synthetic account"),
        ({"--account-id": "1234"}, "12 digits"),
        ({"--deployment-id": "dep_lowercase"}, "dep_<ULID>"),
        ({"--tag": "latest"}, "latest tag is forbidden"),
        ({"--base-image": f"999999999999.dkr.ecr.{REGION}.amazonaws.com/x/base@sha256:{'a' * 64}"}, "must come from"),
        ({"--base-image": f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/x/base:3.11"}, "pinned by @sha256"),
    ],
)
def test_image_publication_rejects_unsafe_inputs(tmp_path: Path, override: dict, message: str) -> None:
    result = _run(PUBLISH_IMAGES, *_image_args(tmp_path, **override), "--dry-run")
    assert result.returncode == 2
    assert message in result.stderr


def test_image_publication_refuses_to_overwrite_output(tmp_path: Path) -> None:
    existing = tmp_path / "release-images.json"
    existing.write_text("{}", encoding="utf-8")
    result = _run(PUBLISH_IMAGES, *_image_args(tmp_path), "--dry-run")
    assert result.returncode == 2
    assert "refusing to overwrite" in result.stderr


def test_frontend_dry_run_builds_from_lockfile_and_never_deletes() -> None:
    result = _run(
        PUBLISH_FRONTEND,
        "--account-id", ACCOUNT,
        "--bucket", f"scanalyze-{ACCOUNT}-frontend",
        "--distribution-id", "E2SYNTHETIC123",
        "--dry-run",
    )
    assert result.returncode == 0, result.stderr
    output = result.stdout
    assert re.search(r"npm --prefix \S+ ci", output)
    assert re.search(r"npm --prefix \S+ run build", output)
    assert f"s3://scanalyze-{ACCOUNT}-frontend/" in output
    assert "--exclude \\*config.json" in output or "--exclude '*config.json'" in output
    assert "--delete" not in output
    assert "create-invalidation --distribution-id E2SYNTHETIC123" in output


def test_frontend_rejects_a_bucket_the_edge_layer_does_not_serve() -> None:
    result = _run(PUBLISH_FRONTEND, "--account-id", ACCOUNT, "--bucket", "some-other-bucket", "--dry-run")
    assert result.returncode == 2
    assert f"scanalyze-{ACCOUNT}-frontend" in result.stderr


def test_renderer_fills_the_reviewed_template_and_adds_the_ocr_poller() -> None:
    renderer = _renderer()
    routing = json.loads(ROUTING.read_text(encoding="utf-8"))
    document = renderer.render(routing, _release(), desired_count=1)

    definitions = {item["name"]: item for item in document["service_definitions"]}
    assert set(definitions) == {f"scanalyze-{service}" for service in SERVICES} | {"scanalyze-ocr-poll-worker"}
    for item in definitions.values():
        assert re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", item["image"])
        assert item["image"].startswith(f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/{SANITIZED}/scanalyze/")
        assert item["desired_count"] == 1
    assert definitions["scanalyze-ocr-poll-worker"]["image"] == definitions["scanalyze-ocr-worker"]["image"]
    assert definitions["scanalyze-ingest-api"]["port"] == 80
    assert definitions["scanalyze-ingest-api"]["health_check_path"] == "/health"
    assert document["alb_service_routes"] == routing["alb_service_routes"]


def test_renderer_can_skip_the_poller_and_keeps_template_counts() -> None:
    renderer = _renderer()
    routing = json.loads(ROUTING.read_text(encoding="utf-8"))
    document = renderer.render(routing, _release(), include_poller=False)
    names = [item["name"] for item in document["service_definitions"]]
    assert "scanalyze-ocr-poll-worker" not in names
    counts = {item["name"]: item["desired_count"] for item in document["service_definitions"]}
    template_counts = {item["name"]: item["desired_count"] for item in routing["service_definitions"]}
    assert counts == template_counts


@pytest.mark.parametrize(
    "release",
    [
        _release(schema_version="other.v1"),
        _release(account_id="000"),
        _release(images={service: "sha256:short" for service in SERVICES}),
        _release(images={"ingest-api": f"sha256:{'a' * 64}"}),
    ],
)
def test_renderer_rejects_invalid_release_images(tmp_path: Path, release: dict) -> None:
    renderer = _renderer()
    path = tmp_path / "release-images.json"
    path.write_text(json.dumps(release), encoding="utf-8")
    with pytest.raises(renderer.RenderError):
        renderer.load_release(path)


def test_renderer_cli_refuses_to_overwrite(tmp_path: Path) -> None:
    renderer = _renderer()
    release_path = tmp_path / "release-images.json"
    release_path.write_text(json.dumps(_release()), encoding="utf-8")
    out = tmp_path / "services.auto.tfvars.json"
    assert renderer.main(["--release-images", str(release_path), "--out", str(out)]) == 0
    rendered = json.loads(out.read_text(encoding="utf-8"))
    assert len(rendered["service_definitions"]) == 8
    assert renderer.main(["--release-images", str(release_path), "--out", str(out)]) == 1
