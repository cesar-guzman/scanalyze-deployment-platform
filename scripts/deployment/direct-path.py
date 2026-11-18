#!/usr/bin/env python3
"""Owner-run direct-path deployment kit for one non-production environment (GUG-543).

The direct path deploys Scanalyze into a new, dedicated AWS account without
the factory-v2 orchestrator (scripts/deployment/scanalyze-deploy.sh): there is
no target registry, ACCOUNT_READY v2 record, execution lock, platform
authority, PEP, ledger, broker or SSM contract publication. For each root the
owner runs terraform init/plan/apply and saves `terraform output -json`.

This kit renders the two per-layer inputs the owner needs:

  layers                       print the direct-path apply order
  backend <layer> --config     write <layer>.backend.hcl for the S3 backend
  tfvars <layer> --config --outputs-dir --out
                               render <layer>.tfvars.json from the config and
                               the saved outputs of every upstream layer

Contract variables are projected exactly as the orchestrator would project
them (deployment/contract-catalog.v1.json bindings, and the digest rule of
scripts/deployment/publish-contract.py: SHA-256 over the canonical JSON of the
upstream `contract_payload.outputs`). Inputs that only the factory can supply
are self-attested: the release manifest digest, the ACCOUNT_READY digest, the
release-manifest/v1 and identity-contract/v2 projections, and the edge/v2
digest that addons reads before edge exists. Every root precondition is a
self-consistency check, so those values satisfy them; none is signed or
externally verified. See docs/operations/direct-path-deployment.md.

The kit makes no AWS or network calls and never overwrites a rendered file.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - exercised only without PyYAML
    print("BLOCKED_TOOLING: PyYAML is required (pip install pyyaml)", file=sys.stderr)
    sys.exit(2)

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# The publisher's digest rule; reusing it keeps self-computed digests identical.
from tooling.validate_digest import canonicalize, compute_digest  # noqa: E402


LAYERS_FILE = REPO_ROOT / "deployment" / "layers.yaml"
CATALOG_FILE = REPO_ROOT / "deployment" / "contract-catalog.v1.json"
ROOTS_DIR = REPO_ROOT / "roots"
POLICY_FILE = REPO_ROOT / "policies" / "authorization" / "enterprise-authorization.v1.json"
POLICY_DIGEST_FILE = POLICY_FILE.with_suffix(".sha256")

KIT_VERSION = "scanalyze.direct-path.v1"
RELEASE_RECORD = "direct-path-release.json"
RELEASE_RECORD_KIND = "scanalyze.direct-path.release-record.v1"

DIRECT_PATH_ORDER = (
    "global",
    "network",
    "platform",
    "data-foundation",
    "cicd",
    "identity-control-plane",
    "addons",
    "services",
    "edge-identity",
    "edge",
)
LAYER_NOTES = {
    "cicd": "ECR repositories only: enable_codecommit=false, enable_codepipeline=false",
    "identity-control-plane": "needs the identity Lambda zip in a versioned S3 bucket",
    "addons": "before services: on this branch addons owns the /ecs/<deployment>/<service> log groups",
    "services": "needs the published images (docs/operations/direct-path-publish.md, PR #136)",
}
SKIPPED_LAYERS = {
    "account-ready-gate": "no ACCOUNT_READY v2 record exists; its digest is self-attested in global",
    "platform-authority": "no factory authority on the direct path",
    "artifact-publication": "images are published by the owner (PR #136 publish runbook)",
    "synthetic-validation": "replaced by the manual smoke test in the runbook",
}

# Exact values the downstream roots require (roots/services/contract_validation.tf,
# modules/edge/runtime_config.tf, modules/edge/variables.tf).
REVIEWED_POLICY_VERSION = "1.0.0"
REVIEWED_POLICY_DIGEST = "sha256:34a639992f6c2312176ac7dc12c361daa38201adea6af0c0b1765a17a14754f8"
CANONICAL_SCOPES = {
    "read": "scanalyze.api.v1/read",
    "write": "scanalyze.api.v1/write",
    "admin": "scanalyze.api.v1/admin",
}
SERVICES = (
    "ingest-api",
    "ocr-worker",
    "postprocess-worker",
    "classifier-worker",
    "bank-worker",
    "personal-worker",
    "gov-worker",
)
OCR_POLLER = "ocr-poll-worker"
QUEUE_STAGES = frozenset({
    "ingest", "ocr", "classify", "bank-extract", "personal-extract",
    "gov-extract", "validate", "persist", "notify",
})
FRONTEND_FEATURES = frozenset({"document_upload", "batch_processing", "audit_view", "user_administration"})
NON_PRODUCTION_ENVIRONMENTS = ("sandbox", "dev", "staging")

# Projection metadata the orchestrator reserves (scripts/deployment/contract_projection.py).
RESERVED_PROJECTION_FIELDS = (
    "contract_id",
    "schema_version",
    "customer_id",
    "deployment_id",
    "account_id",
    "region",
    "release_manifest_digest",
    "contract_digest",
)

ULID = "[0-9A-HJKMNP-TV-Z]{26}"
CUSTOMER_ID = re.compile(rf"^cust_{ULID}$")
DEPLOYMENT_ID = re.compile(rf"^dep_{ULID}$")
ACCOUNT_ID = re.compile(r"^[0-9]{12}$")
REGION = re.compile(r"^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$")
SEMVER = re.compile(
    r"^v?[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
HOSTNAME = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
IPV4 = re.compile(r"^[0-9]+(\.[0-9]+){3}$")
ZONE_ID = re.compile(r"^Z[0-9A-Z]{1,32}$")
SHA256_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
KEY_DIGEST = re.compile(r"(?:^|/)sha256[-/:]([0-9a-f]{64})(?=[./_-]|$)")
CLIENT_ID = re.compile(r"^[A-Za-z0-9]{1,128}$")
IMAGE = re.compile(r"^([^@\s]+)@sha256:[0-9a-f]{64}$")
MODEL_ID = re.compile(r"^[a-z0-9]+([.-][a-z0-9]+)*(:[0-9]+)?$")
SSM_PREFIX = re.compile(r"^/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$")
ROUTE_KEY = re.compile(
    r"^(GET|POST|PUT|PATCH|DELETE|HEAD) /([A-Za-z0-9._~-]+|\{[A-Za-z][A-Za-z0-9_]*\})"
    r"(/([A-Za-z0-9._~-]+|\{[A-Za-z][A-Za-z0-9_]*\}))*$"
)
LOG_GROUP_NAME = re.compile(r"^[A-Za-z0-9_\-/.#]{1,512}$")
CERTIFICATE_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")


class KitError(Exception):
    """An expected, fail-closed rendering error with an owner-facing message."""


# ---------------------------------------------------------------------------
# Strict JSON / YAML loading
# ---------------------------------------------------------------------------


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise KitError(f"duplicate JSON key {key!r}")
        document[key] = value
    return document


def _reject_constant(value: str) -> Any:
    raise KitError(f"non-finite JSON constant {value}")


def load_json(path: Path, description: str) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise KitError(f"cannot read {description} at {path}: {exc}") from exc
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant)
    except json.JSONDecodeError as exc:
        raise KitError(f"{description} at {path} is not valid JSON: {exc}") from exc


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys."""


def _construct_mapping(loader: _StrictLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise KitError(f"duplicate config key {key!r} (line {key_node.start_mark.line + 1})")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def write_exclusive(path: Path, document: Any) -> None:
    """Create a new JSON file; never overwrite an existing one."""
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise KitError(f"{path} already exists; refusing to overwrite it") from exc
    except OSError as exc:
        raise KitError(f"cannot create {path}: {exc}") from exc
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True, ensure_ascii=True)
        handle.write("\n")


# ---------------------------------------------------------------------------
# Terraform variable discovery (no HCL dependency)
# ---------------------------------------------------------------------------

_HEREDOC = re.compile(r"<<-?([A-Za-z_][A-Za-z0-9_]*)[ \t]*\r?\n")
_VARIABLE_BLOCK = re.compile(r'(?m)^[ \t]*variable[ \t]+"[^"\n]*"[ \t]*\{')
_ATTRIBUTE = re.compile(r"^[ \t]*([A-Za-z_][A-Za-z0-9_-]*)[ \t]*=(?!=)")


def _mask_hcl(text: str) -> str:
    """Blank comments, string contents and heredoc bodies, keeping offsets.

    Quotes delimiting top-level strings are kept so names can be read back from
    the original text at the same offsets. Template interpolations, including
    nested quoted strings inside them, are blanked too.
    """
    chars = list(text)
    size = len(text)

    def blank(start: int, end: int) -> None:
        for index in range(start, min(end, size)):
            if chars[index] != "\n":
                chars[index] = " "

    def skip_template(start: int) -> int:
        depth = 1
        index = start
        while index < size:
            char = text[index]
            if char == '"':
                end = skip_string(index)
                blank(index, end)
                index = end
                continue
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    blank(index, index + 1)
                    return index + 1
            blank(index, index + 1)
            index += 1
        raise KitError("unterminated template interpolation in Terraform source")

    def skip_string(start: int) -> int:
        index = start + 1
        while index < size:
            if text[index] == "\\":
                blank(index, index + 2)
                index += 2
                continue
            if text[index] == '"':
                return index + 1
            if text.startswith(("$${", "%%{"), index):
                blank(index, index + 3)
                index += 3
                continue
            if text.startswith(("${", "%{"), index):
                blank(index, index + 2)
                index = skip_template(index + 2)
                continue
            blank(index, index + 1)
            index += 1
        raise KitError("unterminated string in Terraform source")

    index = 0
    while index < size:
        char = text[index]
        if char == "#" or text.startswith("//", index):
            end = text.find("\n", index)
            end = size if end < 0 else end
            blank(index, end)
            index = end
        elif text.startswith("/*", index):
            end = text.find("*/", index + 2)
            end = size if end < 0 else end + 2
            blank(index, end)
            index = end
        elif char == '"':
            index = skip_string(index)
        elif text.startswith("<<", index) and (match := _HEREDOC.match(text, index)):
            position = match.end()
            while True:
                line_end = text.find("\n", position)
                line = text[position:] if line_end < 0 else text[position:line_end]
                if line.strip() == match.group(1):
                    end = size if line_end < 0 else line_end
                    break
                if line_end < 0:
                    raise KitError("unterminated heredoc in Terraform source")
                position = line_end + 1
            blank(match.end(), end)
            index = end
        else:
            index += 1
    return "".join(chars)


@dataclass(frozen=True)
class VariableInfo:
    name: str
    has_default: bool
    default_literal: Any = None


def _matching_brace(masked: str, open_index: int) -> int:
    depth = 0
    for index in range(open_index, len(masked)):
        if masked[index] == "{":
            depth += 1
        elif masked[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    raise KitError("unbalanced braces in Terraform source")


def parse_variables(text: str) -> dict[str, VariableInfo]:
    """Return every top-level variable block, with whether it has a default."""
    masked = _mask_hcl(text)
    variables: dict[str, VariableInfo] = {}
    position = 0
    while True:
        match = _VARIABLE_BLOCK.search(masked, position)
        if match is None:
            return variables
        quote_start = text.index('"', match.start())
        name = text[quote_start + 1:text.index('"', quote_start + 1)]
        open_index = match.end() - 1
        close_index = _matching_brace(masked, open_index)
        body_masked = masked[open_index + 1:close_index]
        body_text = text[open_index + 1:close_index]
        depth = 0
        default_literal: Any = None
        has_default = False
        offset = 0
        for masked_line in body_masked.split("\n"):
            original_line = body_text[offset:offset + len(masked_line)]
            offset += len(masked_line) + 1
            if depth == 0:
                attribute = _ATTRIBUTE.match(masked_line)
                if attribute and attribute.group(1) == "default":
                    has_default = True
                    expression = original_line.split("=", 1)[1].strip()
                    try:
                        default_literal = json.loads(expression)
                    except json.JSONDecodeError:
                        default_literal = None
            depth += masked_line.count("{") - masked_line.count("}")
        if name in variables:
            raise KitError(f"variable {name!r} is declared twice")
        variables[name] = VariableInfo(name, has_default, default_literal)
        position = close_index + 1


def root_variables(layer: str, roots_dir: Path = ROOTS_DIR) -> dict[str, VariableInfo]:
    root = roots_dir / layer
    if not root.is_dir():
        raise KitError(f"root {root} does not exist")
    variables: dict[str, VariableInfo] = {}
    for path in sorted(root.glob("*.tf")):
        for name, info in parse_variables(path.read_text(encoding="utf-8")).items():
            if name in variables:
                raise KitError(f"variable {name!r} is declared twice in {root}")
            variables[name] = info
    if not variables:
        raise KitError(f"no variables found in {root}")
    return variables


# ---------------------------------------------------------------------------
# Deployment config
# ---------------------------------------------------------------------------

TOP_LEVEL_KEYS = frozenset({
    "kit", "customer_id", "deployment_id", "account_id", "region", "environment",
    "release_version", "aws_partition", "state_bucket", "state_region", "state_kms_key_id",
    "domain_name", "route53_zone_id", "alb_tls_server_name", "internal_certificate_arn",
    "api_access_log_group_arn", "global", "network", "identity", "microservices",
    "services", "edge_identity", "edge",
})
ALWAYS_REQUIRED = (
    "kit", "customer_id", "deployment_id", "account_id", "region", "environment",
    "release_version", "state_bucket", "domain_name",
)
# Config values a layer needs beyond ALWAYS_REQUIRED (dotted paths).
LAYER_REQUIRED_CONFIG = {
    "platform": ("internal_certificate_arn",),
    "cicd": ("microservices",),
    "identity-control-plane": ("identity.lambda_artifact",),
    "services": ("services.inputs_file",),
    "edge-identity": (
        "alb_tls_server_name",
        "api_access_log_group_arn",
        "edge_identity.api_authorization_routes",
        "edge_identity.legacy_identity_handoff_complete",
    ),
    "edge": ("route53_zone_id",),
}


@dataclass
class Config:
    path: Path
    data: dict[str, Any]

    def has(self, dotted: str) -> bool:
        node: Any = self.data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node or node[part] is None:
                return False
            node = node[part]
        return True

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node or node[part] is None:
                return default
            node = node[part]
        return node

    def require(self, dotted: str) -> Any:
        if not self.has(dotted):
            raise KitError(f"config value {dotted!r} is missing in {self.path}")
        return self.get(dotted)

    @property
    def customer_id(self) -> str:
        return self.data["customer_id"]

    @property
    def deployment_id(self) -> str:
        return self.data["deployment_id"]

    @property
    def account_id(self) -> str:
        return self.data["account_id"]

    @property
    def region(self) -> str:
        return self.data["region"]

    @property
    def environment(self) -> str:
        return self.data["environment"]

    @property
    def release_version(self) -> str:
        return self.data["release_version"]

    @property
    def domain_name(self) -> str:
        return self.data["domain_name"]


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise KitError(message)


def _string(value: Any, name: str, pattern: re.Pattern[str] | None = None, hint: str = "") -> str:
    _expect(isinstance(value, str), f"config value {name!r} must be a string{' (quote it)' if isinstance(value, (int, float)) else ''}")
    if pattern is not None:
        _expect(bool(pattern.fullmatch(value)), f"config value {name!r} is invalid{': ' + hint if hint else ''}")
    return value


def _string_list(value: Any, name: str) -> list[str]:
    _expect(isinstance(value, list) and all(isinstance(item, str) for item in value), f"config value {name!r} must be a list of strings")
    _expect(len(set(value)) == len(value), f"config value {name!r} has duplicates")
    return value


def _closed_mapping(value: Any, name: str, allowed: set[str] | frozenset[str]) -> dict[str, Any]:
    _expect(isinstance(value, dict), f"config section {name!r} must be a mapping")
    unknown = sorted(set(value) - set(allowed))
    _expect(not unknown, f"config section {name!r} has unknown keys: {', '.join(map(str, unknown))}")
    return value


def _bucket_name(value: Any, name: str) -> str:
    bucket = _string(value, name, BUCKET, "must be a general-purpose S3 bucket name")
    _expect(
        not any(token in bucket for token in ("..", ".-", "-."))
        and not bucket.startswith(("xn--", "sthree-", "amzn-s3-demo-"))
        and not bucket.endswith(("-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3"))
        and not IPV4.fullmatch(bucket),
        f"config value {name!r} is not a valid general-purpose S3 bucket name",
    )
    return bucket


def _validate_config(data: dict[str, Any], path: Path) -> None:
    unknown = sorted(set(data) - TOP_LEVEL_KEYS)
    _expect(not unknown, f"unknown config keys in {path}: {', '.join(map(str, unknown))}")
    for key in ALWAYS_REQUIRED:
        _expect(data.get(key) is not None, f"config value {key!r} is missing in {path}")

    _expect(data["kit"] == KIT_VERSION, f"config value 'kit' must be {KIT_VERSION!r}")
    customer = _string(data["customer_id"], "customer_id", CUSTOMER_ID, "expected cust_<ULID>")
    deployment = _string(data["deployment_id"], "deployment_id", DEPLOYMENT_ID, "expected dep_<ULID>")
    _expect(customer != deployment, "customer_id and deployment_id must differ")
    account = _string(data["account_id"], "account_id", ACCOUNT_ID, "expected 12 digits")
    region = _string(data["region"], "region", REGION, "expected an AWS region such as us-east-1")
    environment = _string(data["environment"], "environment")
    _expect(
        environment in NON_PRODUCTION_ENVIRONMENTS,
        f"environment must be one of {', '.join(NON_PRODUCTION_ENVIRONMENTS)}; the direct path is non-production only",
    )
    release = _string(data["release_version"], "release_version", SEMVER, "expected a semantic version (the edge root requires it)")
    _expect(len(release) <= 128, "release_version must be at most 128 characters")
    _expect(data.get("aws_partition", "aws") == "aws", "aws_partition must be 'aws' (modules/data-foundation/kms.tf hard-codes the aws partition)")
    _bucket_name(data["state_bucket"], "state_bucket")
    if data.get("state_region") is not None:
        _string(data["state_region"], "state_region", REGION)
    if data.get("state_kms_key_id") is not None:
        _string(
            data["state_kms_key_id"], "state_kms_key_id",
            re.compile(r"^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:(key|alias)/[A-Za-z0-9/_-]+$"),
            "expected a KMS key or alias ARN",
        )
    domain = _string(data["domain_name"], "domain_name", HOSTNAME, "expected a lowercase DNS hostname")
    _expect(len(domain) <= 253, "domain_name must be at most 253 characters")

    if data.get("route53_zone_id") is not None:
        _string(data["route53_zone_id"], "route53_zone_id", ZONE_ID, "expected a Route 53 hosted zone ID such as Z0123456789ABCDEFGHIJ")
    if data.get("alb_tls_server_name") is not None:
        name = _string(data["alb_tls_server_name"], "alb_tls_server_name", HOSTNAME, "expected a lowercase FQDN")
        _expect(not IPV4.fullmatch(name), "alb_tls_server_name must not be an IP address")
    if data.get("internal_certificate_arn") is not None:
        arn = _string(data["internal_certificate_arn"], "internal_certificate_arn")
        prefix = f"arn:aws:acm:{region}:{account}:certificate/"
        _expect(
            arn.startswith(prefix) and bool(CERTIFICATE_ID.fullmatch(arn[len(prefix):])),
            f"internal_certificate_arn must be an ACM certificate in {region} and account {account} ({prefix}<uuid>)",
        )
    if data.get("api_access_log_group_arn") is not None:
        arn = _string(data["api_access_log_group_arn"], "api_access_log_group_arn")
        prefix = f"arn:aws:logs:{region}:{account}:log-group:"
        _expect(
            arn.startswith(prefix) and bool(LOG_GROUP_NAME.fullmatch(arn[len(prefix):])),
            f"api_access_log_group_arn must be {prefix}<name> without ':*' or wildcards",
        )

    if data.get("global") is not None:
        section = _closed_mapping(data["global"], "global", {"bedrock_classifier_model_ids", "bedrock_extractor_model_ids", "runtime_parameter_path_prefix"})
        for key in ("bedrock_classifier_model_ids", "bedrock_extractor_model_ids"):
            if section.get(key) is not None:
                models = _string_list(section[key], f"global.{key}")
                _expect(bool(models) and all(MODEL_ID.fullmatch(model) for model in models), f"global.{key} must list exact model IDs without wildcards")
        if section.get("runtime_parameter_path_prefix") is not None:
            _string(section["runtime_parameter_path_prefix"], "global.runtime_parameter_path_prefix", SSM_PREFIX)

    if data.get("network") is not None:
        _closed_mapping(data["network"], "network", {"vpc_cidr", "private_subnet_cidrs", "public_subnet_cidrs"})

    if data.get("identity") is not None:
        identity = _closed_mapping(data["identity"], "identity", {"lambda_artifact", "m2m_bindings", "alarm_actions"})
        if identity.get("lambda_artifact") is not None:
            _lambda_locator(identity["lambda_artifact"])
        _m2m_bindings(identity.get("m2m_bindings") or [], customer, deployment)
        for arn in _string_list(identity.get("alarm_actions") or [], "identity.alarm_actions"):
            _expect(arn.startswith(f"arn:aws:sns:{region}:{account}:") and "*" not in arn, "identity.alarm_actions must be same-account, same-region SNS topic ARNs")

    if data.get("microservices") is not None:
        _microservices(data["microservices"])

    if data.get("services") is not None:
        services = _closed_mapping(data["services"], "services", {"inputs_file"})
        if services.get("inputs_file") is not None:
            _string(services["inputs_file"], "services.inputs_file")

    if data.get("edge_identity") is not None:
        edge_identity = _closed_mapping(data["edge_identity"], "edge_identity", {"api_authorization_routes", "legacy_identity_handoff_complete"})
        if edge_identity.get("legacy_identity_handoff_complete") is not None:
            _expect(
                edge_identity["legacy_identity_handoff_complete"] is True,
                "edge_identity.legacy_identity_handoff_complete must be true; assert it only because this new account never held edge-identity Cognito state",
            )
        if edge_identity.get("api_authorization_routes") is not None:
            _routes(edge_identity["api_authorization_routes"])

    if data.get("edge") is not None:
        edge = _closed_mapping(data["edge"], "edge", {"frontend_features"})
        if edge.get("frontend_features") is not None:
            features = _closed_mapping(edge["frontend_features"], "edge.frontend_features", FRONTEND_FEATURES)
            _expect(all(isinstance(value, bool) for value in features.values()), "edge.frontend_features values must be true or false")


def _lambda_locator(value: Any) -> dict[str, str]:
    locator = _closed_mapping(value, "identity.lambda_artifact", {"bucket", "key", "object_version", "sha256_b64"})
    for key in ("bucket", "key", "object_version"):
        _expect(locator.get(key) is not None, f"config value 'identity.lambda_artifact.{key}' is missing")
    bucket = _bucket_name(locator["bucket"], "identity.lambda_artifact.bucket")
    key = _string(locator["key"], "identity.lambda_artifact.key")
    digests = KEY_DIGEST.findall(key)
    _expect(
        len(digests) == 1,
        "identity.lambda_artifact.key must contain exactly one sha256-<64 lowercase hex> segment, the SHA-256 of the zip",
    )
    version = _string(locator["object_version"], "identity.lambda_artifact.object_version")
    _expect(
        version != "" and version.lower() != "null" and len(version.encode("utf-8")) <= 1024,
        "identity.lambda_artifact.object_version must be the object's S3 VersionId (bucket versioning enabled)",
    )
    derived = base64.b64encode(bytes.fromhex(digests[0])).decode("ascii")
    if locator.get("sha256_b64") is not None:
        given = _string(locator["sha256_b64"], "identity.lambda_artifact.sha256_b64")
        try:
            decoded = base64.b64decode(given, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise KitError("identity.lambda_artifact.sha256_b64 is not base64") from exc
        _expect(len(decoded) == 32 and given == derived, "identity.lambda_artifact.sha256_b64 does not match the sha256 segment of the key")
    return {"bucket": bucket, "key": key, "object_version": version, "sha256_b64": derived}


def _m2m_bindings(value: Any, customer: str, deployment: str) -> list[dict[str, Any]]:
    _expect(isinstance(value, list), "identity.m2m_bindings must be a list")
    bindings = []
    for index, raw in enumerate(value):
        binding = _closed_mapping(raw, f"identity.m2m_bindings[{index}]", {"client_id", "required_scopes"})
        client_id = _string(binding.get("client_id"), f"identity.m2m_bindings[{index}].client_id", CLIENT_ID, "expected the Cognito app client ID")
        scopes = _string_list(binding.get("required_scopes"), f"identity.m2m_bindings[{index}].required_scopes")
        _expect(bool(scopes) and set(scopes) <= set(CANONICAL_SCOPES.values()), f"identity.m2m_bindings[{index}].required_scopes must be canonical scanalyze.api.v1 scopes")
        bindings.append({"client_id": client_id, "customer_id": customer, "deployment_id": deployment, "required_scopes": scopes})
    client_ids = [binding["client_id"] for binding in bindings]
    _expect(len(set(client_ids)) == len(client_ids), "identity.m2m_bindings has duplicate client IDs")
    return sorted(bindings, key=lambda item: item["client_id"])


def _microservices(value: Any) -> dict[str, dict[str, str]]:
    services = _closed_mapping(value, "microservices", set(SERVICES))
    _expect(set(services) == set(SERVICES), f"microservices must define exactly: {', '.join(SERVICES)}")
    rendered = {}
    for service in SERVICES:
        entry = _closed_mapping(services[service], f"microservices.{service}", {"service_name", "ecr_repo_name"})
        _expect(entry.get("service_name") == service, f"microservices.{service}.service_name must be {service!r}")
        _expect(
            entry.get("ecr_repo_name") == f"scanalyze/{service}",
            f"microservices.{service}.ecr_repo_name must be 'scanalyze/{service}' (the publish runbook pushes to <dep-ulid>/scanalyze/<service>)",
        )
        rendered[service] = {"service_name": service, "ecr_repo_name": f"scanalyze/{service}"}
    return rendered


def _routes(value: Any) -> dict[str, list[str]]:
    _expect(isinstance(value, dict) and value, "edge_identity.api_authorization_routes must be a non-empty mapping")
    for route_key, scopes in value.items():
        _expect(isinstance(route_key, str) and route_key != "$default" and bool(ROUTE_KEY.fullmatch(route_key)), f"invalid API route key {route_key!r}")
        _expect(
            isinstance(scopes, list) and len(scopes) == 1 and scopes[0] in CANONICAL_SCOPES.values(),
            f"API route {route_key!r} needs exactly one canonical scanalyze.api.v1 scope",
        )
    return value


def load_config(path: Path) -> Config:
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise KitError(f"cannot read config {path}: {exc}") from exc
    try:
        data = yaml.load(text, Loader=_StrictLoader)  # noqa: S506 - SafeLoader subclass
    except yaml.YAMLError as exc:
        raise KitError(f"config {path} is not valid YAML: {exc}") from exc
    _expect(isinstance(data, dict), f"config {path} must be a YAML mapping")
    _validate_config(data, path)
    return Config(path=path.resolve(), data=data)


# ---------------------------------------------------------------------------
# Layers, backend and release record
# ---------------------------------------------------------------------------


def _layer_record(layer: str) -> dict[str, Any]:
    document = yaml.safe_load(LAYERS_FILE.read_text(encoding="utf-8"))
    for record in document.get("layers", []):
        if record.get("layer") == layer:
            return record
    raise KitError(f"layer {layer!r} is not declared in {LAYERS_FILE}")


def state_key(layer: str, config: Config) -> str:
    template = _layer_record(layer).get("state_key")
    _expect(isinstance(template, str), f"layer {layer!r} has no state_key in {LAYERS_FILE}")
    key = template.replace("{deployment_id}", config.deployment_id).replace("{region}", config.region)
    _expect("{" not in key and "}" not in key, f"state_key for {layer!r} has an unknown placeholder: {template}")
    return key


def backend_document(layer: str, config: Config) -> str:
    _check_layer(layer)
    lines = [
        f"# S3 backend for roots/{layer}; rendered by scripts/deployment/direct-path.py",
        f"bucket              = {json.dumps(config.data['state_bucket'])}",
        f"key                 = {json.dumps(state_key(layer, config))}",
        f"region              = {json.dumps(config.get('state_region', config.region))}",
        "encrypt             = true",
        "use_lockfile        = true",
        f"allowed_account_ids = [{json.dumps(config.account_id)}]",
    ]
    if config.has("state_kms_key_id"):
        lines.append(f"kms_key_id          = {json.dumps(config.data['state_kms_key_id'])}")
    return "\n".join(lines) + "\n"


def _release_inputs(config: Config) -> dict[str, str]:
    return {
        "customer_id": config.customer_id,
        "deployment_id": config.deployment_id,
        "account_id": config.account_id,
        "region": config.region,
        "environment": config.environment,
        "release_version": config.release_version,
    }


def release_manifest_digest(config: Config) -> str:
    """The deterministic, self-attested release manifest digest for a deployment."""
    return compute_digest(canonicalize({"kind": "scanalyze.direct-path.release-manifest.v1", **_release_inputs(config)}))


def release_record(config: Config) -> dict[str, Any]:
    return {
        "kind": RELEASE_RECORD_KIND,
        "inputs": _release_inputs(config),
        "release_manifest_digest": release_manifest_digest(config),
        "self_attested": True,
        "derivation": "sha256 over the canonical JSON of the inputs plus kind=scanalyze.direct-path.release-manifest.v1",
    }


def resolve_release_digest(config: Config, outputs_dir: Path, layer: str) -> tuple[str, bool]:
    """Return the release digest and whether global must record it now."""
    digest = release_manifest_digest(config)
    path = outputs_dir / RELEASE_RECORD
    if path.exists():
        existing = load_json(path, "release record")
        _expect(
            isinstance(existing, dict)
            and existing.get("kind") == RELEASE_RECORD_KIND
            and existing.get("inputs") == _release_inputs(config)
            and existing.get("release_manifest_digest") == digest,
            f"{path} records a different deployment or release than {config.path}; "
            "every layer must use the release digest recorded when global was rendered",
        )
        return digest, False
    _expect(
        layer == "global",
        f"{path} is missing: render global first; it records the deployment's release digest",
    )
    return digest, True


def _self_attested_digest(contract_id: str, consumer: str, config: Config, release_digest: str) -> str:
    return compute_digest(canonicalize({
        "kind": "scanalyze.direct-path.self-attested-contract.v1",
        "contract_id": contract_id,
        "consumer": consumer,
        "customer_id": config.customer_id,
        "deployment_id": config.deployment_id,
        "account_id": config.account_id,
        "region": config.region,
        "release_manifest_digest": release_digest,
    }))


def _check_layer(layer: str) -> None:
    if layer in SKIPPED_LAYERS:
        raise KitError(f"{layer} is not part of the direct path: {SKIPPED_LAYERS[layer]}")
    _expect(layer in DIRECT_PATH_ORDER, f"unknown layer {layer!r}; expected one of: {', '.join(DIRECT_PATH_ORDER)}")


# ---------------------------------------------------------------------------
# Upstream outputs and contract projection
# ---------------------------------------------------------------------------


def _major(contract_id: str) -> str:
    return contract_id.rsplit("/v", 1)[1]


def _assert_account_bound(value: Any, account_id: str, where: str) -> None:
    """Every account-scoped ARN in an upstream output must belong to the deployment account."""
    if isinstance(value, dict):
        for key, item in value.items():
            _assert_account_bound(item, account_id, f"{where}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _assert_account_bound(item, account_id, f"{where}[{index}]")
    elif isinstance(value, str) and value.startswith("arn:"):
        parts = value.split(":")
        if len(parts) > 4 and parts[4]:
            _expect(parts[4] == account_id, f"{where} belongs to account {parts[4]}, not {account_id}")


def load_layer_outputs(outputs_dir: Path, layer: str, contract_id: str, config: Config) -> dict[str, Any]:
    """Read `terraform output -json` of an applied layer and return its contract outputs."""
    path = outputs_dir / f"{layer}.outputs.json"
    if not path.is_file():
        raise KitError(
            f"upstream outputs for {layer} are missing: {path}. Apply roots/{layer}, then run "
            f"`terraform -chdir=roots/{layer} output -json > {path}`"
        )
    document = load_json(path, f"{layer} outputs")
    _expect(isinstance(document, dict) and document, f"{path} must be the JSON object printed by `terraform output -json`")
    payload = document.get("contract_payload")
    _expect(
        isinstance(payload, dict) and isinstance(payload.get("value"), dict),
        f"{path} has no contract_payload output; save the full `terraform output -json` of roots/{layer}",
    )
    _expect(payload.get("sensitive") is not True, f"{path}: contract_payload must not be sensitive")
    value = payload["value"]
    outputs = value.get("outputs")
    _expect(isinstance(outputs, dict) and outputs, f"{path}: contract_payload.outputs must be a non-empty object")
    _expect(
        str(value.get("schema_version")) == _major(contract_id),
        f"{path}: contract_payload.schema_version is {value.get('schema_version')!r}, but {contract_id} is expected",
    )
    _assert_account_bound(outputs, config.account_id, f"{layer}.contract_payload.outputs")
    return outputs


def project_contract(
    contract_id: str,
    scope: str,
    outputs: dict[str, Any],
    contract_digest: str,
    config: Config,
    release_digest: str,
) -> dict[str, Any]:
    """Mirror scripts/deployment/contract_projection.py::_contract_projection."""
    projection: dict[str, Any] = {
        "contract_id": contract_id,
        "schema_version": _major(contract_id),
        "customer_id": config.customer_id,
        "deployment_id": config.deployment_id,
        "account_id": config.account_id,
        "region": "global" if scope == "global" else config.region,
        "release_manifest_digest": release_digest,
        "contract_digest": contract_digest,
    }
    for key, value in outputs.items():
        if key in RESERVED_PROJECTION_FIELDS:
            _expect(
                projection[key] == value,
                f"{contract_id} output {key}={value!r} conflicts with the deployment value {projection[key]!r}",
            )
        projection[key] = copy.deepcopy(value)
    return projection


class _Rendered:
    """Variable values plus where each one came from."""

    def __init__(self, layer: str) -> None:
        self.layer = layer
        self.values: dict[str, Any] = {}
        self.sources: dict[str, str] = {}
        self.record_release = False

    def add(self, name: str, value: Any, source: str) -> None:
        if name in self.values:
            raise KitError(f"{self.layer}: variable {name!r} would be set twice ({self.sources[name]}; {source})")
        self.values[name] = value
        self.sources[name] = source


def _catalog() -> dict[str, Any]:
    catalog = load_json(CATALOG_FILE, "contract catalog")
    _expect(isinstance(catalog, dict) and isinstance(catalog.get("contracts"), dict), f"{CATALOG_FILE} is invalid")
    return catalog


def consumed_contracts(layer: str) -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
    """Catalog contracts bound to a consumer layer, in catalog order."""
    consumed = []
    for contract_id, record in _catalog()["contracts"].items():
        binding = record.get("consumer_bindings", {}).get(layer)
        if isinstance(binding, dict):
            consumed.append((contract_id, record, binding))
    return consumed


def upstream_layers(layer: str) -> list[str]:
    """Applied layers whose saved outputs a layer reads on the direct path."""
    _check_layer(layer)
    position = DIRECT_PATH_ORDER.index(layer)
    producers = []
    for _, record, _ in consumed_contracts(layer):
        producer = record.get("producer")
        if record.get("authority") == "terraform-root" and producer in DIRECT_PATH_ORDER and DIRECT_PATH_ORDER.index(producer) < position:
            producers.append(producer)
    return producers


def _apply_binding(
    rendered: _Rendered,
    contract_id: str,
    binding: dict[str, Any],
    *,
    projection: dict[str, Any] | None,
    outputs: dict[str, Any] | None,
    digest: str,
    source: str,
) -> None:
    """Mirror scripts/deployment/contract_projection.py::bind_variables."""
    if binding.get("contract_variable") is not None:
        _expect(projection is not None, f"{contract_id}: cannot self-attest {binding['contract_variable']}")
        rendered.add(binding["contract_variable"], projection, source)
    for output_name, variable in binding.get("output_variables", {}).items():
        _expect(outputs is not None, f"{contract_id}: cannot self-attest output {output_name}")
        _expect(output_name in outputs, f"{contract_id} outputs have no {output_name!r} for {variable}")
        rendered.add(variable, copy.deepcopy(outputs[output_name]), source)
    for metadata, variables in binding.get("metadata_variables", {}).items():
        value = {
            "contract_digest": digest,
            "output_schema_version": contract_id,
            "output_schema_major": _major(contract_id),
        }.get(metadata)
        _expect(value is not None, f"{contract_id}: unsupported metadata binding {metadata!r}")
        for variable in variables:
            rendered.add(variable, value, f"{source} {metadata}")


# ---------------------------------------------------------------------------
# Self-attested identity inputs (shapes from tooling/identity_adapters.py)
# ---------------------------------------------------------------------------


def _reviewed_policy() -> tuple[str, str]:
    policy = load_json(POLICY_FILE, "authorization policy")
    version = policy.get("policy_version") if isinstance(policy, dict) else None
    digest = POLICY_DIGEST_FILE.read_text(encoding="utf-8").strip()
    _expect(
        version == REVIEWED_POLICY_VERSION and digest == REVIEWED_POLICY_DIGEST,
        f"{POLICY_FILE.name} is {version} {digest}, but roots/services requires "
        f"{REVIEWED_POLICY_VERSION} {REVIEWED_POLICY_DIGEST}; re-review the policy binding first",
    )
    return version, digest


def release_manifest_contract(config: Config, release_digest: str) -> dict[str, Any]:
    locator = _lambda_locator(config.require("identity.lambda_artifact"))
    contract: dict[str, Any] = {
        "contract_id": "release-manifest/v1",
        "schema_version": "1",
        "customer_id": config.customer_id,
        "deployment_id": config.deployment_id,
        "account_id": config.account_id,
        "region": config.region,
        "release_version": config.release_version,
        "manifest_digest": release_digest,
        # One zip serves both handlers (identity_control_plane.entrypoints).
        "pre_token_artifact": dict(locator),
        "control_processor_artifact": dict(locator),
    }
    contract["contract_digest"] = compute_digest(canonicalize(contract))
    return contract


def m2m_registry_contract(config: Config) -> dict[str, Any]:
    bindings = _m2m_bindings(config.get("identity.m2m_bindings") or [], config.customer_id, config.deployment_id)
    registry: dict[str, Any] = {
        "contract_id": "identity-contract/v2",
        "schema_version": "2",
        "customer_id": config.customer_id,
        "deployment_id": config.deployment_id,
        "action_scope_sets": {action: [scope] for action, scope in CANONICAL_SCOPES.items()},
        "m2m_bindings": bindings,
    }
    registry["contract_digest"] = compute_digest(canonicalize(registry))
    return registry


# ---------------------------------------------------------------------------
# Services inputs (output of render-direct-service-definitions.py, PR #136)
# ---------------------------------------------------------------------------


def _bare(name: str) -> str:
    return name[len("scanalyze-"):] if name.startswith("scanalyze-") else name


def load_services_inputs(
    config: Config,
    declared: dict[str, VariableInfo],
    task_roles: dict[str, Any],
    ecr_repository_urls: dict[str, Any],
) -> dict[str, Any]:
    path = Path(config.require("services.inputs_file"))
    if not path.is_absolute():
        path = config.path.parent / path
    _expect(
        path.is_file(),
        f"services inputs {path} are missing; render them with scripts/deployment/render-direct-service-definitions.py (PR #136)",
    )
    document = load_json(path, "services inputs")
    _expect(
        isinstance(document, dict) and set(document) == {"service_definitions", "alb_service_routes"},
        f"{path} must contain exactly service_definitions and alb_service_routes",
    )
    definitions = document["service_definitions"]
    routes = document["alb_service_routes"]
    _expect(isinstance(definitions, list) and definitions, f"{path}: service_definitions must be a non-empty list")
    _expect(isinstance(routes, dict), f"{path}: alb_service_routes must be an object")
    repositories = {url for url in ecr_repository_urls.values() if isinstance(url, str)}
    poller_supported = "runtime_wiring" in declared
    names = []
    for definition in definitions:
        _expect(isinstance(definition, dict) and isinstance(definition.get("name"), str), f"{path}: every service definition needs a name")
        name = definition["name"]
        names.append(name)
        image = IMAGE.fullmatch(str(definition.get("image", "")))
        _expect(image is not None, f"{path}: {name} image must be pinned by @sha256 digest")
        _expect(
            image.group(1) in repositories,
            f"{path}: {name} image is not in one of this deployment's ECR repositories (cicd ecr_repository_urls)",
        )
        if _bare(name) == OCR_POLLER:
            _expect(
                poller_supported,
                f"{path}: {name} needs the runtime_wiring input of PR #135, which roots/services does not declare "
                "yet; re-render with --without-ocr-poller",
            )
        else:
            _expect(
                name in task_roles,
                f"{path}: {name} has no workload role; the global outputs name roles {', '.join(sorted(task_roles))}",
            )
    _expect(len(set(names)) == len(names), f"{path}: service names must be unique")
    return {"service_definitions": definitions, "alb_service_routes": routes}


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

# Deployment-wide config values emitted to every root that declares them.
_DEPLOYMENT_VARIABLES = ("customer_id", "deployment_id", "account_id", "region", "environment", "release_version", "domain_name")


def render_tfvars(layer: str, config: Config, outputs_dir: Path) -> _Rendered:
    """Render the tfvars of one root; fails closed on any missing or inconsistent input.

    Pure: it writes nothing. `record_release` on the result tells the caller
    that global must record the release digest (see write_tfvars).
    """
    _check_layer(layer)
    for dotted in LAYER_REQUIRED_CONFIG.get(layer, ()):
        config.require(dotted)
    outputs_dir = Path(outputs_dir)
    _expect(outputs_dir.is_dir(), f"outputs directory {outputs_dir} does not exist")
    declared = root_variables(layer)
    release_digest, record_release = resolve_release_digest(config, outputs_dir, layer)
    rendered = _Rendered(layer)
    rendered.record_release = record_release
    position = DIRECT_PATH_ORDER.index(layer)
    upstream: dict[str, dict[str, Any]] = {}

    for name in _DEPLOYMENT_VARIABLES:
        if name in declared:
            rendered.add(name, config.data[name], "config")
    if "release_manifest_digest" in declared:
        rendered.add("release_manifest_digest", release_digest, f"self-attested ({RELEASE_RECORD})")

    for contract_id, record, binding in consumed_contracts(layer):
        authority = record.get("authority")
        producer = record.get("producer")
        if authority == "terraform-root" and producer in DIRECT_PATH_ORDER and DIRECT_PATH_ORDER.index(producer) < position:
            outputs = load_layer_outputs(outputs_dir, producer, contract_id, config)
            upstream[producer] = outputs
            digest = compute_digest(canonicalize(outputs))
            projection = project_contract(contract_id, record.get("scope", "regional"), outputs, digest, config, release_digest)
            _apply_binding(rendered, contract_id, binding, projection=projection, outputs=outputs, digest=digest, source=f"upstream {contract_id}")
        elif authority in ("terraform-root", "account-baseline"):
            # account-ready/v2 has no record on the direct path; edge/v2 is applied after addons.
            digest = _self_attested_digest(contract_id, layer, config, release_digest)
            _apply_binding(rendered, contract_id, binding, projection=None, outputs=None, digest=digest, source=f"self-attested {contract_id}")
        elif authority == "release":
            if binding.get("contract_variable"):
                contract = release_manifest_contract(config, release_digest)
                rendered.add(binding["contract_variable"], contract, "self-attested release-manifest/v1 (config lambda_artifact)")
                rendered.add("expected_release_manifest_contract_digest", contract["contract_digest"], "self-attested release-manifest/v1 digest")
        elif authority == "identity-registry":
            registry = m2m_registry_contract(config)
            rendered.add(binding["contract_variable"], registry, "self-attested identity-contract/v2 (config m2m_bindings)")
            rendered.add("expected_m2m_registry_contract_digest", registry["contract_digest"], "self-attested identity-contract/v2 digest")
        else:
            raise KitError(f"{layer}: catalog contract {contract_id} has unsupported authority {authority!r}")

    _layer_specific(layer, config, declared, upstream, rendered)
    _check_declared(layer, declared, rendered)
    return rendered


def _layer_specific(
    layer: str,
    config: Config,
    declared: dict[str, VariableInfo],
    upstream: dict[str, dict[str, Any]],
    rendered: _Rendered,
) -> None:
    if layer in ("global", "identity-control-plane") and "aws_partition" in declared:
        rendered.add("aws_partition", "aws", "fixed: the direct path supports the aws partition only")

    if layer == "global":
        for key in ("bedrock_classifier_model_ids", "bedrock_extractor_model_ids", "runtime_parameter_path_prefix"):
            if config.has(f"global.{key}"):
                _expect(key in declared, f"config global.{key} is set, but roots/global does not declare {key}")
                rendered.add(key, config.get(f"global.{key}"), "config")

    elif layer == "network":
        for key in ("vpc_cidr", "private_subnet_cidrs", "public_subnet_cidrs"):
            if config.has(f"network.{key}"):
                _expect(
                    key in declared,
                    f"config network.{key} is set, but roots/network does not expose it; "
                    "modules/network defaults apply (10.0.0.0/16, AZ IDs use1-az1 and use1-az2)",
                )
                rendered.add(key, config.get(f"network.{key}"), "config")
        if "private_subnet_cidrs" not in declared or not config.has("network.private_subnet_cidrs"):
            _expect(
                config.region == "us-east-1",
                "roots/network keeps the module default subnets in AZ IDs use1-az1 and use1-az2, "
                "which exist only in us-east-1; use region us-east-1",
            )

    elif layer == "platform":
        rendered.add("internal_certificate_arn", config.require("internal_certificate_arn"), "config")

    elif layer == "data-foundation":
        if "browser_origins" in declared:  # PR #136
            rendered.add("browser_origins", [f"https://{config.domain_name}"], "derived: https://<domain_name> (PR #136)")

    elif layer == "cicd":
        rendered.add("microservices", _microservices(config.require("microservices")), "config")
        rendered.add("enable_codecommit", False, "fixed: ECR only")
        rendered.add("enable_codepipeline", False, "fixed: ECR only")

    elif layer == "identity-control-plane":
        version, digest = _reviewed_policy()
        rendered.add("policy_version", version, f"fixed: {POLICY_FILE.relative_to(REPO_ROOT)}")
        rendered.add("policy_digest", digest, f"fixed: {POLICY_DIGEST_FILE.relative_to(REPO_ROOT)}")
        rendered.add("control_processor_enabled", True, "fixed: required by the root")
        alarm_actions = config.get("identity.alarm_actions") or []
        if alarm_actions:
            rendered.add("alarm_actions", alarm_actions, "config")

    elif layer == "services":
        inputs = load_services_inputs(
            config,
            declared,
            upstream["global"].get("ecs_task_role_arns", {}),
            upstream["cicd"].get("ecr_repository_urls", {}),
        )
        rendered.add("service_definitions", inputs["service_definitions"], "config services.inputs_file (PR #136 renderer)")
        rendered.add("alb_service_routes", inputs["alb_service_routes"], "config services.inputs_file (PR #136 renderer)")
        if "runtime_wiring" in declared:  # PR #135
            data = upstream["data-foundation"]
            queues = data.get("sqs_queue_urls")
            _expect(
                isinstance(queues, dict) and set(queues) == QUEUE_STAGES
                and all(isinstance(url, str) and url.startswith("https://sqs.") for url in queues.values()),
                "data-foundation sqs_queue_urls must map the nine canonical stages to HTTPS SQS URLs",
            )
            rendered.add("runtime_wiring", {
                "runtime_environment": config.environment,
                "documents_table_name": data["documents_table_name"],
                "documents_bucket_name": data["documents_bucket_name"],
                "stage_queue_urls": queues,
            }, "upstream data-foundation/v2 outputs + config environment (PR #135)")

    elif layer == "edge-identity":
        rendered.add("alb_tls_server_name", config.require("alb_tls_server_name"), "config")
        rendered.add("api_access_log_group_arn", config.require("api_access_log_group_arn"), "config")
        rendered.add("cors_allowed_origins", [f"https://{config.domain_name}"], "derived: https://<domain_name>")
        rendered.add("api_authorization_routes", config.require("edge_identity.api_authorization_routes"), "config")
        rendered.add("legacy_identity_handoff_complete", config.require("edge_identity.legacy_identity_handoff_complete"), "config (owner assertion)")

    elif layer == "edge":
        rendered.add("route53_zone_id", config.require("route53_zone_id"), "config")
        rendered.add(
            "frontend_bucket_domain_name",
            f"scanalyze-{config.account_id}-frontend.s3.{config.region}.amazonaws.com",
            "derived: scanalyze-<account>-frontend bucket (modules/edge/runtime_config.tf)",
        )
        if config.has("edge.frontend_features"):
            rendered.add("frontend_features", config.get("edge.frontend_features"), "config")


def _check_declared(layer: str, declared: dict[str, VariableInfo], rendered: _Rendered) -> None:
    undeclared = sorted(set(rendered.values) - set(declared))
    _expect(not undeclared, f"{layer}: the kit would set undeclared variables: {', '.join(undeclared)}")
    missing = sorted(name for name, info in declared.items() if not info.has_default and name not in rendered.values)
    _expect(not missing, f"roots/{layer} requires variables the kit cannot source: {', '.join(missing)}")
    accepted = declared.get("accepted_schema_versions")
    if accepted is not None and "upstream_schema_version" in rendered.values and "accepted_schema_versions" not in rendered.values:
        _expect(
            isinstance(accepted.default_literal, list) and rendered.values["upstream_schema_version"] in accepted.default_literal,
            f"{layer}: upstream schema version {rendered.values['upstream_schema_version']!r} is not in the root's default accepted_schema_versions",
        )
    for name, value in rendered.values.items():
        if name == "expected_upstream_digest":
            _expect(value == rendered.values.get("upstream_contract_digest"), f"{layer}: upstream digest pair differs")
        elif name.startswith("expected_") and name.endswith("_digest"):
            contract = rendered.values.get(name[len("expected_"):-len("_digest")])
            _expect(isinstance(contract, dict) and contract.get("contract_digest") == value, f"{layer}: {name} does not match its contract")
        if name.endswith("_digest") and isinstance(value, str):
            _expect(bool(SHA256_DIGEST.fullmatch(value)), f"{layer}: {name} is not sha256:<64 hex>")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _cmd_layers(args: argparse.Namespace) -> int:
    if args.names:
        print("\n".join(DIRECT_PATH_ORDER))
        return 0
    print("Direct-path apply order (one dedicated non-production account):")
    for index, layer in enumerate(DIRECT_PATH_ORDER, start=1):
        record = _layer_record(layer)
        print(f"{index:>2}. {layer:<23} roots/{layer:<23} state key {record['state_key']}")
        reads = ", ".join(f"{name}.outputs.json" for name in upstream_layers(layer)) or "no upstream outputs"
        print(f"    reads: {reads}")
        if layer in LAYER_NOTES:
            print(f"    note:  {LAYER_NOTES[layer]}")
    print("Not applied on the direct path:")
    for layer, reason in SKIPPED_LAYERS.items():
        print(f"  - {layer}: {reason}")
    return 0


def _cmd_backend(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    document = backend_document(args.layer, config)
    out = Path(args.out) if args.out else Path.cwd() / f"{args.layer}.backend.hcl"
    _expect(out.suffix == ".hcl", "--out must end with .hcl")
    if out.exists():
        _expect(out.read_text(encoding="utf-8") == document, f"{out} already exists with different content; refusing to overwrite it")
        print(f"PASS: {out} is already up to date")
        return 0
    _expect(out.parent.is_dir(), f"directory {out.parent} does not exist")
    descriptor = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(document)
    print(f"PASS: wrote {out} (key {state_key(args.layer, config)})")
    return 0


def write_tfvars(layer: str, config: Config, outputs_dir: Path, out: Path) -> _Rendered:
    """Render, record the release digest (global only, first time), then write --out."""
    _expect(out.name.endswith(".tfvars.json"), "--out must end with .tfvars.json so Terraform reads it as JSON")
    _expect(not out.exists(), f"{out} already exists; refusing to overwrite it")
    _expect(out.parent.is_dir(), f"directory {out.parent} does not exist")
    rendered = render_tfvars(layer, config, outputs_dir)
    if rendered.record_release:
        write_exclusive(Path(outputs_dir) / RELEASE_RECORD, release_record(config))
    write_exclusive(out, rendered.values)
    return rendered


def _cmd_tfvars(args: argparse.Namespace) -> int:
    out = Path(args.out)
    config = load_config(args.config)
    rendered = write_tfvars(args.layer, config, Path(args.outputs_dir), out)
    print(f"PASS: wrote {out} ({len(rendered.values)} variables)")
    if rendered.record_release:
        print(f"PASS: recorded the release digest in {Path(args.outputs_dir) / RELEASE_RECORD}")
    width = max(len(name) for name in rendered.values)
    for name in sorted(rendered.values):
        print(f"  {name:<{width}}  {rendered.sources[name]}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)

    layers = commands.add_parser("layers", help="print the direct-path apply order")
    layers.add_argument("--names", action="store_true", help="print only the layer names, one per line")
    layers.set_defaults(handler=_cmd_layers)

    backend = commands.add_parser("backend", help="write <layer>.backend.hcl")
    backend.add_argument("layer")
    backend.add_argument("--config", required=True, type=Path)
    backend.add_argument("--out", help="default: ./<layer>.backend.hcl")
    backend.set_defaults(handler=_cmd_backend)

    tfvars = commands.add_parser("tfvars", help="render <layer>.tfvars.json")
    tfvars.add_argument("layer")
    tfvars.add_argument("--config", required=True, type=Path)
    tfvars.add_argument("--outputs-dir", required=True, type=Path, help="directory holding <layer>.outputs.json files")
    tfvars.add_argument("--out", required=True, help="new file ending in .tfvars.json")
    tfvars.set_defaults(handler=_cmd_tfvars)

    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except KitError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
