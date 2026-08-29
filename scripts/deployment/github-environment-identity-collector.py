#!/usr/bin/env python3
"""Collect private GitHub Environment identity artifacts with read-only GETs."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling.github_environment_identity_collector import (  # noqa: E402
    GitHubEnvironmentCollectorError,
    TOKEN_ENV_NAME,
    collect_to_private_directory,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity-template", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--token-env-name",
        default="GITHUB_TOKEN",
        help="name of the environment variable containing the short-lived token",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not TOKEN_ENV_NAME.fullmatch(args.token_env_name):
        print("FAIL: COLLECTOR_CONFIGURATION_INVALID", file=sys.stderr)
        return 1
    token = os.environ.get(args.token_env_name, "")
    try:
        collect_to_private_directory(
            identity_template_path=args.identity_template,
            output_dir=args.output_dir,
            token=token,
        )
    except GitHubEnvironmentCollectorError as exc:
        print(f"FAIL: {exc.code}", file=sys.stderr)
        return 1
    except Exception:
        print("FAIL: GITHUB_ENVIRONMENT_COLLECTION_INTERNAL_ERROR", file=sys.stderr)
        return 1
    print("PASS: GitHub Environment identity and anchor collected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
