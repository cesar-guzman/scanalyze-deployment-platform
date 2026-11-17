"""GUG-541 — workload identity policies stay in sync with their sources.

The global layer grants each workload role only the AWS actions its service
code calls, on resource ARNs derived from names that later layers create.
These offline checks read Terraform and Python source only; they never
initialize providers or contact AWS. Plan-level behavior is covered by
modules/global/tests/workload_policies.tftest.hcl.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
GLOBAL_DIR = REPO_ROOT / "modules" / "global"
GLOBAL_POLICIES = GLOBAL_DIR / "workload_policies.tf"
GLOBAL_IAM = GLOBAL_DIR / "iam.tf"
GLOBAL_VARIABLES = GLOBAL_DIR / "variables.tf"
DATA_FOUNDATION = REPO_ROOT / "modules" / "data-foundation"
IDENTITY = REPO_ROOT / "modules" / "identity-control-plane"
WORKERS = REPO_ROOT / "backend" / "workers"

SERVICE_SOURCES = {
    "ingest-api": WORKERS / "scanalyze-ingest-api" / "app",
    "ocr-worker": WORKERS / "scanalyze-ocr-worker" / "src",
    "postprocess-worker": WORKERS / "scanalyze-postprocess-worker" / "src",
    "classifier-worker": WORKERS / "scanalyze-classifier-worker" / "src",
    "bank-worker": WORKERS / "scanalyze-bank-worker" / "src",
    "personal-worker": WORKERS / "scanalyze-personal-worker" / "src",
    "gov-worker": WORKERS / "scanalyze-gov-worker" / "src",
}

# boto3 method -> IAM action, for the calls these services make.
S3_OBJECT_METHODS = {
    "get_object": "s3:GetObject",
    "head_object": "s3:GetObject",
    "put_object": "s3:PutObject",
    "delete_object": "s3:DeleteObject",
    "copy_object": "s3:PutObject",
}
S3_LIST_METHODS = ("list_objects_v2", "list_objects")
DYNAMODB_METHODS = {
    "get_item": "dynamodb:GetItem",
    "put_item": "dynamodb:PutItem",
    "update_item": "dynamodb:UpdateItem",
    "delete_item": "dynamodb:DeleteItem",
    "query": "dynamodb:Query",
    "scan": "dynamodb:Scan",
    "batch_get_item": "dynamodb:BatchGetItem",
    "batch_write_item": "dynamodb:BatchWriteItem",
}
TEXTRACT_GRANTED = ("start_document_text_detection", "get_document_text_detection")
TEXTRACT_UNGRANTED = (
    "analyze_document",
    "analyze_expense",
    "detect_document_text",
    "start_document_analysis",
    "get_document_analysis",
    "start_expense_analysis",
    "get_expense_analysis",
)
BEDROCK_METHODS = ("converse", "converse_stream", "invoke_model", "invoke_model_with_response_stream")
SQS_CONSUMER_METHODS = ("receive_message", "delete_message", "change_message_visibility")


def _block(text: str, opening: str) -> str:
    """Return the text inside the braces that follow the first match of opening."""
    match = re.search(opening, text)
    assert match, f"block not found: {opening}"
    start = text.index("{", match.start())
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start + 1 : index]
    raise AssertionError(f"unbalanced block: {opening}")


def _strings(fragment: str) -> list[str]:
    return re.findall(r'"([^"]+)"', fragment)


def _data_foundation_topology() -> dict[str, tuple[frozenset[str], str]]:
    block = _block((DATA_FOUNDATION / "locals.tf").read_text(), r"\bqueue_topology\s*=")
    topology = {}
    for match in re.finditer(r'^\s*"?([a-z-]+)"?\s*=\s*\{(.*?)^\s*\}', block, re.S | re.M):
        body = match.group(2)
        producers = re.search(r"\bproducers\s*=\s*\[([^\]]*)\]", body)
        consumer = re.search(r'\bconsumer\s*=\s*"([^"]+)"', body)
        assert producers and consumer, f"stage {match.group(1)} lacks producers or consumer"
        topology[match.group(1)] = (frozenset(_strings(producers.group(1))), consumer.group(1))
    return topology


def _global_topology() -> dict[str, tuple[frozenset[str], str]]:
    block = _block(GLOBAL_POLICIES.read_text(), r"\bworkload_queue_topology\s*=")
    topology = {}
    pattern = r'^\s*"?([a-z-]+)"?\s*=\s*\{\s*producers\s*=\s*\[([^\]]*)\],\s*consumer\s*=\s*"([^"]+)"\s*\}'
    for match in re.finditer(pattern, block, re.M):
        topology[match.group(1)] = (frozenset(_strings(match.group(2))), match.group(3))
    return topology


def _access_profiles() -> dict[str, dict[str, object]]:
    block = _block(GLOBAL_POLICIES.read_text(), r"\bworkload_access_profiles\s*=")
    profiles = {}
    for match in re.finditer(r'^\s*"([a-z-]+)"\s*=\s*\{(.*?)^\s*\}', block, re.S | re.M):
        body = match.group(2)

        def field(name: str) -> str:
            found = re.search(rf"^\s*{name}\s*=\s*(.+)$", body, re.M)
            assert found, f"profile {match.group(1)} lacks {name}"
            return found.group(1).strip()

        profiles[match.group(1)] = {
            "s3_object_actions": set(_strings(field("s3_object_actions"))),
            "s3_list_bucket": field("s3_list_bucket") == "true",
            "table_actions": set(_strings(field("table_actions"))),
            "sends_queue_url": field("sends_queue_url") == "true",
            "textract": field("textract") == "true",
            "bedrock": _strings(field("bedrock"))[0],
            "cognito_admin": field("cognito_admin") == "true",
        }
    return profiles


def _variable_default(text: str, name: str) -> list[str]:
    block = _block(text, rf'variable\s+"{name}"')
    default = re.search(r"^\s*default\s*=\s*(\[[^\]]*\]|\"[^\"]*\")", block, re.M)
    assert default, f"{name} has no default"
    return _strings(default.group(1))


def _service_source(service: str) -> str:
    root = SERVICE_SOURCES[service]
    files = [
        path
        for path in sorted(root.rglob("*.py"))
        if "tests" not in path.relative_to(root).parts and not path.name.startswith("test_")
    ]
    assert files, f"no source files for {service}"
    return "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in files)


def _calls(source: str, method: str) -> bool:
    return re.search(rf"\.{method}\(", source) is not None


def test_global_queue_topology_matches_data_foundation() -> None:
    expected = _data_foundation_topology()
    assert len(expected) == 9
    assert _global_topology() == expected


def test_derived_resource_names_match_their_owning_layers() -> None:
    policies = GLOBAL_POLICIES.read_text()
    s3 = (DATA_FOUNDATION / "s3.tf").read_text()
    dynamodb = (DATA_FOUNDATION / "dynamodb.tf").read_text()
    sqs = (DATA_FOUNDATION / "sqs.tf").read_text()

    bucket_name = '${lower(replace(var.deployment_id, "_", "-"))}-documents'
    assert re.search(r"bucket\s*=\s*\"" + re.escape(bucket_name) + '"', s3)
    assert f":s3:::{bucket_name}" in policies

    assert re.search(r'name\s*=\s*"\$\{var\.deployment_id\}-documents"', dynamodb)
    assert "table/${var.deployment_id}-documents" in policies

    assert '"${var.deployment_id}-${each.key}-stage-queue"' in sqs
    assert ":${var.deployment_id}-${stage}-stage-queue" in policies


def test_tag_conditions_match_the_tagged_resources() -> None:
    kms_key = _block((DATA_FOUNDATION / "kms.tf").read_text(), r'resource\s+"aws_kms_key"\s+"data"')
    assert re.search(r'layer\s*=\s*"data-foundation"', kms_key)
    assert re.search(r'purpose\s*=\s*"application-data-encryption"', kms_key)
    assert re.search(r'deployment_id\s*=\s*var\.deployment_id', kms_key)

    user_pool = _block((IDENTITY / "cognito.tf").read_text(), r'resource\s+"aws_cognito_user_pool"\s+"main"')
    assert re.search(r'purpose\s*=\s*"enterprise-human-identity"', user_pool)
    assert "local.common_tags" in user_pool
    common_tags = _block((IDENTITY / "locals.tf").read_text(), r"\bcommon_tags\s*=")
    assert re.search(r"deployment_id\s*=\s*var\.deployment_id", common_tags)

    for path in (GLOBAL_POLICIES, GLOBAL_IAM):
        text = path.read_text()
        assert '"aws:ResourceTag/purpose"       = "enterprise-human-identity"' in text
    policies = GLOBAL_POLICIES.read_text()
    assert '"aws:ResourceTag/layer"         = "data-foundation"' in policies
    assert '"aws:ResourceTag/purpose"       = "application-data-encryption"' in policies


def test_default_bedrock_models_match_service_code() -> None:
    variables = GLOBAL_VARIABLES.read_text()
    default_pattern = r'config\.get\("BEDROCK_MODEL_ID",\s*default="([^"]+)"\)'

    classifier_defaults = set(re.findall(default_pattern, _service_source("classifier-worker")))
    assert classifier_defaults == set(_variable_default(variables, "bedrock_classifier_model_ids"))

    extractor_defaults = set()
    for service in ("bank-worker", "personal-worker", "gov-worker"):
        extractor_defaults |= set(re.findall(default_pattern, _service_source(service)))
    assert extractor_defaults == set(_variable_default(variables, "bedrock_extractor_model_ids"))


def test_every_workload_role_has_an_access_profile() -> None:
    services = _variable_default(GLOBAL_VARIABLES.read_text(), "service_names")
    assert set(services) == set(_access_profiles()) == set(SERVICE_SOURCES)


def test_boundary_allows_every_action_the_identity_policies_grant() -> None:
    boundary = _block(GLOBAL_IAM.read_text(), r'resource\s+"aws_iam_policy"\s+"workload_permissions_boundary"')
    allowed = set(re.findall(r'"([a-z0-9-]+:[A-Za-z]+)"', boundary))
    granted = set(re.findall(r'"([a-z0-9-]+:[A-Za-z]+)"', GLOBAL_POLICIES.read_text()))
    granted = {action for action in granted if not action.startswith(("aws:", "kms:ViaService"))}
    assert granted <= allowed, f"boundary blocks granted actions: {sorted(granted - allowed)}"
    assert '"textract:*"' not in boundary
    assert '"bedrock:*"' not in boundary


@pytest.mark.parametrize("service", sorted(SERVICE_SOURCES))
def test_granted_actions_cover_the_service_code(service: str) -> None:
    source = _service_source(service)
    profile = _access_profiles()[service]
    topology = _global_topology()
    policies = GLOBAL_POLICIES.read_text()

    required_s3 = {action for method, action in S3_OBJECT_METHODS.items() if _calls(source, method)}
    assert required_s3 <= profile["s3_object_actions"], f"{service} calls S3 actions it is not granted"
    if any(_calls(source, method) for method in S3_LIST_METHODS):
        assert profile["s3_list_bucket"], f"{service} lists objects without s3:ListBucket"

    required_table = {action for method, action in DYNAMODB_METHODS.items() if _calls(source, method)}
    if re.search(r'["\']ConditionCheck["\']', source):
        required_table.add("dynamodb:ConditionCheckItem")
    assert required_table <= profile["table_actions"], f"{service} calls DynamoDB actions it is not granted"

    if any(_calls(source, method) for method in TEXTRACT_GRANTED):
        assert profile["textract"], f"{service} calls Textract without the text-detection grant"
    assert not any(_calls(source, method) for method in TEXTRACT_UNGRANTED), (
        f"{service} calls a Textract API that no policy grants"
    )

    if any(_calls(source, method) for method in BEDROCK_METHODS):
        assert profile["bedrock"] != "none", f"{service} calls Bedrock without a model grant"
    else:
        assert profile["bedrock"] == "none", f"{service} is granted Bedrock but never calls it"

    produces = any(service in producers for producers, _ in topology.values())
    consumes = any(consumer == service for _, consumer in topology.values())
    if _calls(source, "send_message"):
        assert produces, f"{service} sends messages but produces no stage"
    if _calls(source, "get_queue_url"):
        assert profile["sends_queue_url"], f"{service} resolves queue URLs without sqs:GetQueueUrl"
    if any(_calls(source, method) for method in SQS_CONSUMER_METHODS):
        assert consumes, f"{service} consumes messages but owns no stage queue"

    admin_methods = set(re.findall(r"\.(admin_[a-z_]+)\(", source))
    if admin_methods:
        assert profile["cognito_admin"], f"{service} calls Cognito admin APIs without a grant"
        for method in admin_methods:
            action = "cognito-idp:" + "".join(part.capitalize() for part in method.split("_"))
            assert f'"{action}"' in policies, f"{service} calls {method} but {action} is not granted"
    else:
        assert not profile["cognito_admin"], f"{service} is granted Cognito admin but never calls it"
