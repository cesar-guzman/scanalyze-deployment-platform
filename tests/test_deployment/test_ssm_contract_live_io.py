"""Hermetic tests for immutable SSM contract live I/O."""
from __future__ import annotations

import json
import os
import subprocess
from copy import deepcopy
from typing import Any, Mapping, Sequence

import pytest

from tooling.ssm_contract_live_io import (
    CallerIdentity,
    LiveContractIoError,
    SubprocessAwsCliRunner,
    canonical_parameter_name,
    publish_immutable_ssm_contract,
    resolve_required_ssm_contracts,
    verify_caller_identity,
)
from tooling.validate_digest import canonicalize, compute_digest


ACCOUNT_ID = "111222333444"
REGION = "us-east-1"
CUSTOMER_ID = "cust_01J5A1B2C3D4E5F6G7H8J9K0M1"
DEPLOYMENT_ID = "dep_01J5A1B2C3D4E5F6G7H8J9K0M1"
RELEASE_DIGEST = "sha256:" + ("a" * 64)
CONTRACT_ID = "global/v1"
PATH_TEMPLATE = (
    "/scanalyze/deployments/{deployment_id}/contracts/global/v1/"
    "releases/{release_digest}/digests/{contract_digest}"
)


def _catalog() -> dict[str, Any]:
    return {
        "schema_version": "1",
        "contracts": {
            CONTRACT_ID: {
                "authority": "terraform-root",
                "producer": "global",
                "scope": "global",
                "transport": {"kind": "ssm", "path_template": PATH_TEMPLATE},
            }
        },
    }


def _envelope() -> dict[str, Any]:
    outputs = {
        "ecs_execution_role_arn": f"arn:aws:iam::{ACCOUNT_ID}:role/Execution",
        "ecs_task_role_arns": {
            "scanalyze-ingest-api": f"arn:aws:iam::{ACCOUNT_ID}:role/Ingest"
        },
    }
    return {
        "schema_version": "2",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "aws_account_id": ACCOUNT_ID,
        "region": "global",
        "scope": "global",
        "layer": "global",
        "producer": "roots/global",
        "release_version": "2026.07.14",
        "release_digest": RELEASE_DIGEST,
        "output_schema_version": CONTRACT_ID,
        "outputs": outputs,
        "contract_digest": compute_digest(canonicalize(outputs)),
        "produced_at": "2026-07-14T00:00:00Z",
        "terraform_workspace": "default",
        "state_key": f"{DEPLOYMENT_ID}/global/terraform.tfstate",
        "module_source_digest": "sha256:" + ("b" * 64),
    }


def _argument(arguments: Sequence[str], name: str) -> str:
    index = list(arguments).index(name)
    return arguments[index + 1]


class MemoryAwsRunner:
    """In-memory AWS CLI semantic fake; no subprocess or network."""

    def __init__(self, *, paginated: bool = False) -> None:
        self.calls: list[tuple[str, str, str, tuple[str, ...]]] = []
        self.parameters: dict[str, dict[str, Any]] = {}
        self.tags: dict[str, list[dict[str, str]]] = {}
        self.paginated = paginated
        self.inconsistent_exact_read = False
        self.lose_put_response = False
        self._exact_read_count = 0

    def invoke(
        self,
        service: str,
        operation: str,
        *,
        region: str,
        arguments: Sequence[str] = (),
    ) -> Mapping[str, Any]:
        arguments = tuple(arguments)
        self.calls.append((service, operation, region, arguments))
        if (service, operation) == ("sts", "get-caller-identity"):
            return {
                "Account": ACCOUNT_ID,
                "Arn": (
                    f"arn:aws:sts::{ACCOUNT_ID}:"
                    "assumed-role/ScanalyzePlan/synthetic"
                ),
                "UserId": "AROATEST:synthetic",
            }
        if (service, operation) == ("ssm", "put-parameter"):
            name = _argument(arguments, "--name")
            if "--no-overwrite" not in arguments or name in self.parameters:
                raise LiveContractIoError("AWS CLI request was rejected")
            value = _argument(arguments, "--value")
            self.parameters[name] = {
                "Name": name,
                "Type": "String",
                "Value": value,
                "Version": 1,
                "ARN": f"arn:aws:ssm:{REGION}:{ACCOUNT_ID}:parameter{name}",
                "DataType": "text",
            }
            self.tags[name] = json.loads(_argument(arguments, "--tags"))
            if self.lose_put_response:
                raise LiveContractIoError("AWS CLI request did not complete safely")
            return {"Version": 1, "Tier": "Standard"}
        if (service, operation) == ("ssm", "get-parameter"):
            name = _argument(arguments, "--name")
            parameter = deepcopy(self.parameters[name])
            self._exact_read_count += 1
            if self.inconsistent_exact_read and self._exact_read_count % 2 == 0:
                parameter["Value"] += " "
            return {"Parameter": parameter}
        if (service, operation) == ("ssm", "list-tags-for-resource"):
            name = _argument(arguments, "--resource-id")
            return {"TagList": deepcopy(self.tags[name])}
        if (service, operation) == ("ssm", "get-parameters-by-path"):
            prefix = _argument(arguments, "--path")
            matches = [
                deepcopy(value)
                for name, value in sorted(self.parameters.items())
                if name.startswith(prefix + "/")
            ]
            if self.paginated and "--next-token" not in arguments:
                return {"Parameters": [], "NextToken": "page-2"}
            return {"Parameters": matches}
        raise AssertionError((service, operation, arguments))


def _identity(runner: MemoryAwsRunner) -> CallerIdentity:
    return verify_caller_identity(
        runner,
        expected_account_id=ACCOUNT_ID,
        region=REGION,
    )


def test_live_publish_and_paginated_double_read_resolution_are_exact() -> None:
    runner = MemoryAwsRunner(paginated=True)
    identity = _identity(runner)
    envelope = _envelope()

    name = publish_immutable_ssm_contract(
        runner,
        identity=identity,
        catalog=_catalog(),
        envelope=envelope,
    )
    resolved = resolve_required_ssm_contracts(
        runner,
        identity=identity,
        catalog=_catalog(),
        required_contracts={CONTRACT_ID},
        deployment_id=DEPLOYMENT_ID,
        release_digest=RELEASE_DIGEST,
    )

    assert resolved == [envelope]
    assert ":" not in name
    assert "/releases/sha256-" in name
    assert name.endswith(envelope["contract_digest"].replace(":", "-"))
    put = next(call for call in runner.calls if call[1] == "put-parameter")
    assert "--no-overwrite" in put[3]
    assert _argument(put[3], "--tier") == "Standard"
    assert _argument(put[3], "--type") == "String"
    assert len(json.loads(_argument(put[3], "--tags"))) == 7
    list_calls = [call for call in runner.calls if call[1] == "get-parameters-by-path"]
    assert len(list_calls) == 4
    assert all(call[2] == REGION for call in runner.calls)


def test_publication_recovers_lost_create_response_and_exact_reentry() -> None:
    runner = MemoryAwsRunner()
    identity = _identity(runner)
    envelope = _envelope()
    runner.lose_put_response = True

    first_name = publish_immutable_ssm_contract(
        runner,
        identity=identity,
        catalog=_catalog(),
        envelope=envelope,
    )

    runner.lose_put_response = False
    second_name = publish_immutable_ssm_contract(
        runner,
        identity=identity,
        catalog=_catalog(),
        envelope=envelope,
    )

    assert first_name == second_name
    assert [call[1] for call in runner.calls].count("put-parameter") == 2
    assert [call[1] for call in runner.calls].count("get-parameter") == 4
    assert [call[1] for call in runner.calls].count("list-tags-for-resource") == 4


def test_publication_reentry_rejects_different_existing_content() -> None:
    runner = MemoryAwsRunner()
    identity = _identity(runner)
    envelope = _envelope()
    name = canonical_parameter_name(
        path_template=PATH_TEMPLATE,
        contract_id=CONTRACT_ID,
        deployment_id=DEPLOYMENT_ID,
        release_digest=RELEASE_DIGEST,
        contract_digest=envelope["contract_digest"],
    )
    runner.parameters[name] = {
        "Name": name,
        "Type": "String",
        "Value": canonicalize({**envelope, "produced_at": "2026-07-15T00:00:00Z"}).decode(
            "ascii"
        ),
        "Version": 1,
        "ARN": f"arn:aws:ssm:{REGION}:{ACCOUNT_ID}:parameter{name}",
        "DataType": "text",
    }
    runner.tags[name] = []

    with pytest.raises(LiveContractIoError, match="readback does not match"):
        publish_immutable_ssm_contract(
            runner,
            identity=identity,
            catalog=_catalog(),
            envelope=envelope,
        )

    assert [call[1] for call in runner.calls].count("put-parameter") == 1


def test_release_prefix_is_the_only_index_and_ambiguity_fails_closed() -> None:
    runner = MemoryAwsRunner()
    identity = _identity(runner)
    envelope = _envelope()
    publish_immutable_ssm_contract(
        runner,
        identity=identity,
        catalog=_catalog(),
        envelope=envelope,
    )
    other = deepcopy(envelope)
    other["outputs"]["extra"] = "drift"
    other["contract_digest"] = compute_digest(canonicalize(other["outputs"]))
    other_name = canonical_parameter_name(
        path_template=PATH_TEMPLATE,
        contract_id=CONTRACT_ID,
        deployment_id=DEPLOYMENT_ID,
        release_digest=RELEASE_DIGEST,
        contract_digest=other["contract_digest"],
    )
    runner.parameters[other_name] = {
        "Name": other_name,
        "Type": "String",
        "Value": canonicalize(other).decode("ascii"),
        "Version": 1,
        "ARN": f"arn:aws:ssm:{REGION}:{ACCOUNT_ID}:parameter{other_name}",
        "DataType": "text",
    }

    with pytest.raises(LiveContractIoError, match="missing, ambiguous, or inconsistent"):
        resolve_required_ssm_contracts(
            runner,
            identity=identity,
            catalog=_catalog(),
            required_contracts={CONTRACT_ID},
            deployment_id=DEPLOYMENT_ID,
            release_digest=RELEASE_DIGEST,
        )

    assert all(call[1] != "put-parameter" for call in runner.calls[-2:])


def test_double_read_change_fails_closed_without_returning_payload() -> None:
    runner = MemoryAwsRunner()
    identity = _identity(runner)
    publish_immutable_ssm_contract(
        runner,
        identity=identity,
        catalog=_catalog(),
        envelope=_envelope(),
    )
    runner._exact_read_count = 0
    runner.inconsistent_exact_read = True

    with pytest.raises(LiveContractIoError, match="double read is inconsistent") as error:
        resolve_required_ssm_contracts(
            runner,
            identity=identity,
            catalog=_catalog(),
            required_contracts={CONTRACT_ID},
            deployment_id=DEPLOYMENT_ID,
            release_digest=RELEASE_DIGEST,
        )

    assert ACCOUNT_ID not in str(error.value)


def test_publication_rejects_tampered_digest_before_ssm_write() -> None:
    runner = MemoryAwsRunner()
    identity = _identity(runner)
    envelope = _envelope()
    envelope["contract_digest"] = "sha256:" + ("0" * 64)

    with pytest.raises(LiveContractIoError, match="digest is invalid"):
        publish_immutable_ssm_contract(
            runner,
            identity=identity,
            catalog=_catalog(),
            envelope=envelope,
        )

    assert all(call[1] != "put-parameter" for call in runner.calls)


def test_publication_rejects_standard_parameter_overflow_before_write() -> None:
    runner = MemoryAwsRunner()
    identity = _identity(runner)
    envelope = _envelope()
    envelope["outputs"]["large"] = "x" * 5000
    envelope["contract_digest"] = compute_digest(canonicalize(envelope["outputs"]))

    with pytest.raises(LiveContractIoError, match="Standard bound"):
        publish_immutable_ssm_contract(
            runner,
            identity=identity,
            catalog=_catalog(),
            envelope=envelope,
        )

    assert all(call[1] != "put-parameter" for call in runner.calls)


def test_sts_account_mismatch_stops_before_ssm() -> None:
    class WrongAccountRunner(MemoryAwsRunner):
        def invoke(self, *args: Any, **kwargs: Any) -> Mapping[str, Any]:
            response = dict(super().invoke(*args, **kwargs))
            if args[:2] == ("sts", "get-caller-identity"):
                response["Account"] = "999888777666"
            return response

    runner = WrongAccountRunner()
    with pytest.raises(LiveContractIoError, match="expected account"):
        verify_caller_identity(
            runner,
            expected_account_id=ACCOUNT_ID,
            region=REGION,
        )
    assert [call[1] for call in runner.calls] == ["get-caller-identity"]


def test_default_credential_fallback_is_forbidden() -> None:
    with pytest.raises(LiveContractIoError, match="exactly one"):
        SubprocessAwsCliRunner()
    with pytest.raises(LiveContractIoError, match="exactly one"):
        SubprocessAwsCliRunner(profile="readonly", use_runtime_credentials=True)


def test_runtime_runner_disables_profile_endpoint_and_retry_fallbacks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        captured["command"] = command
        captured["environment"] = kwargs["env"]
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(
                {
                    "Account": ACCOUNT_ID,
                    "Arn": (
                        f"arn:aws:sts::{ACCOUNT_ID}:"
                        "assumed-role/ScanalyzePlan/synthetic"
                    ),
                    "UserId": "AROATEST:synthetic",
                }
            ).encode(),
            stderr=b"",
        )

    monkeypatch.setenv("AWS_PROFILE", "unsafe-default")
    monkeypatch.setenv("AWS_DEFAULT_PROFILE", "unsafe-default")
    monkeypatch.setenv("AWS_ENDPOINT_URL_SSM", "https://invalid.example")
    monkeypatch.setattr(subprocess, "run", fake_run)
    runner = SubprocessAwsCliRunner(use_runtime_credentials=True)

    verify_caller_identity(
        runner,
        expected_account_id=ACCOUNT_ID,
        region=REGION,
    )

    environment = captured["environment"]
    assert "AWS_PROFILE" not in environment
    assert "AWS_DEFAULT_PROFILE" not in environment
    assert "AWS_ENDPOINT_URL_SSM" not in environment
    assert environment["AWS_CONFIG_FILE"] == os.devnull
    assert environment["AWS_SHARED_CREDENTIALS_FILE"] == os.devnull
    assert environment["AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"] == "true"
    assert environment["AWS_MAX_ATTEMPTS"] == "1"
    assert captured["command"][:3] == ["aws", "sts", "get-caller-identity"]


def test_catalog_template_cannot_redirect_contract_publication() -> None:
    catalog = _catalog()
    catalog["contracts"][CONTRACT_ID]["transport"]["path_template"] = (
        "/foreign/{deployment_id}/{release_digest}/{contract_digest}"
    )
    runner = MemoryAwsRunner()
    identity = _identity(runner)
    with pytest.raises(LiveContractIoError, match="not canonical"):
        publish_immutable_ssm_contract(
            runner,
            identity=identity,
            catalog=catalog,
            envelope=_envelope(),
        )
    assert all(call[1] != "put-parameter" for call in runner.calls)
