"""GUG-543 — the ingest API route points at the port and health path the image serves.

The express routing file feeds the services layer (target group port, security
group rule and ALB health check). It used port 8080 and /api/v2/health while
the image listens on PORT=80 and serves /health, so the target could never
become healthy. These offline checks keep the two in sync.
"""

from __future__ import annotations

import json
import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
ROUTING = REPO_ROOT / "deployment" / "express-production-routing.json"
INGEST_API = REPO_ROOT / "backend" / "workers" / "scanalyze-ingest-api"


def _ingest_definition() -> dict:
    definitions = json.loads(ROUTING.read_text(encoding="utf-8"))["service_definitions"]
    matches = [item for item in definitions if item["name"].endswith("ingest-api")]
    assert len(matches) == 1
    return matches[0]


def _image_port() -> int:
    dockerfile = (INGEST_API / "Dockerfile").read_text(encoding="utf-8")
    port = re.search(r"\bPORT=(\d+)", dockerfile)
    assert port, "the ingest API Dockerfile must set PORT"
    assert re.search(rf"^EXPOSE {port.group(1)}$", dockerfile, re.M), "EXPOSE must match PORT"
    overridden = [
        item for item in _ingest_definition().get("extra_environment", []) if item["name"].upper() == "PORT"
    ]
    return int(overridden[0]["value"]) if overridden else int(port.group(1))


def _served_health_paths() -> set[str]:
    source = (INGEST_API / "app" / "api" / "health.py").read_text(encoding="utf-8")
    return set(re.findall(r'@router\.get\("([^"]+)"\)', source))


def test_routing_uses_the_port_the_image_listens_on() -> None:
    assert _ingest_definition()["port"] == _image_port()


def test_health_check_uses_a_path_the_api_serves() -> None:
    assert _ingest_definition()["health_check_path"] in _served_health_paths()
