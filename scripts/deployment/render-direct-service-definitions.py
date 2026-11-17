#!/usr/bin/env python3
"""Render the services layer's service inputs for a direct-path deployment (GUG-543).

Fills the reviewed routing template (deployment/express-production-routing.json:
sizes, ports, health checks and ALB routes) with the image digests that
scripts/deployment/publish-direct-release.sh published. It also adds the OCR
poller, which runs the OCR image in OCR_POLL mode (GUG-108).

The output is a tfvars JSON file with service_definitions and
alb_service_routes for roots/services. It never overwrites an existing file.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ROUTING = REPO_ROOT / "deployment" / "express-production-routing.json"
RELEASE_SCHEMA = "scanalyze.direct-release-images.v1"
SERVICES = (
    "ingest-api",
    "ocr-worker",
    "postprocess-worker",
    "classifier-worker",
    "bank-worker",
    "personal-worker",
    "gov-worker",
)
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
IMAGE = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")
ACCOUNT = re.compile(r"^[0-9]{12}$")
REGION = re.compile(r"^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$")
DEPLOYMENT = re.compile(r"^dep_[0-9A-HJKMNP-TV-Z]{26}$")
POLLER_TEMPLATE = "scanalyze-ocr-worker"
POLLER_NAME = "scanalyze-ocr-poll-worker"


class RenderError(ValueError):
    pass


def _bare(name: str) -> str:
    return name[len("scanalyze-"):] if name.startswith("scanalyze-") else name


def load_release(path: Path) -> dict:
    release = json.loads(path.read_text(encoding="utf-8"))
    if release.get("schema_version") != RELEASE_SCHEMA:
        raise RenderError(f"release images must use schema {RELEASE_SCHEMA}")
    for field, pattern in (("account_id", ACCOUNT), ("region", REGION), ("deployment_id", DEPLOYMENT)):
        if not isinstance(release.get(field), str) or not pattern.fullmatch(release[field]):
            raise RenderError(f"release images have an invalid {field}")
    images = release.get("images")
    if not isinstance(images, dict) or set(images) != set(SERVICES):
        raise RenderError("release images must list exactly the seven services")
    for service, digest in images.items():
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            raise RenderError(f"invalid digest for {service}")
    return release


def render(routing: dict, release: dict, desired_count: int | None = None, include_poller: bool = True) -> dict:
    sanitized_deployment = release["deployment_id"].replace("_", "-").lower()
    definitions = []
    for template in routing["service_definitions"]:
        service = _bare(template["name"])
        if service not in release["images"]:
            raise RenderError(f"no published digest for {template['name']}")
        definition = copy.deepcopy(template)
        image = (
            definition["image"]
            .replace("{digest}", release["images"][service])
            .replace("{account_id}", release["account_id"])
            .replace("{region}", release["region"])
            .replace("{deployment_id}", sanitized_deployment)
        )
        if not IMAGE.fullmatch(image) or "{" in image:
            raise RenderError(f"rendered image for {template['name']} is not an immutable digest reference")
        definition["image"] = image
        if desired_count is not None:
            definition["desired_count"] = desired_count
        definitions.append(definition)

    names = [definition["name"] for definition in definitions]
    if {_bare(name) for name in names} != set(SERVICES) or len(names) != len(set(names)):
        raise RenderError("the routing template must define each of the seven services exactly once")

    if include_poller:
        ocr = next(definition for definition in definitions if definition["name"] == POLLER_TEMPLATE)
        poller = copy.deepcopy(ocr)
        poller["name"] = POLLER_NAME
        if desired_count is None:
            poller["desired_count"] = 1
        definitions.append(poller)

    return {
        "service_definitions": definitions,
        "alb_service_routes": copy.deepcopy(routing.get("alb_service_routes", {})),
    }


def write_exclusive(path: Path, document: dict) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--release-images", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--routing", type=Path, default=DEFAULT_ROUTING)
    parser.add_argument("--desired-count", type=int, help="Override every service's desired_count, for example 1 for a pilot.")
    parser.add_argument("--without-ocr-poller", action="store_true", help="Do not add the OCR_POLL service.")
    args = parser.parse_args(argv)
    try:
        if args.desired_count is not None and not 0 <= args.desired_count <= 10:
            raise RenderError("--desired-count must be between 0 and 10")
        release = load_release(args.release_images)
        routing = json.loads(args.routing.read_text(encoding="utf-8"))
        document = render(routing, release, args.desired_count, not args.without_ocr_poller)
        write_exclusive(args.out, document)
    except FileExistsError:
        print(f"FAIL: {args.out} already exists; refusing to overwrite", file=sys.stderr)
        return 1
    except (RenderError, KeyError, StopIteration, OSError, json.JSONDecodeError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(f"PASS: wrote {args.out} with {len(document['service_definitions'])} service definitions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
