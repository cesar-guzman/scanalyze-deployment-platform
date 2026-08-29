from __future__ import annotations

import base64
import copy
import json
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

import jsonschema
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from tooling.github_environment_identity_collector import (
    ANCHOR_FILENAME,
    DECODED_SECRET_TRANSPORT_PATH_ENV,
    EXPECTED_GITHUB_APP_PERMISSIONS,
    EXPECTED_ENVIRONMENT_VARIABLES,
    GITHUB_APP_ID_ENV,
    GITHUB_APP_INSTALLATION_ID_ENV,
    GITHUB_APP_PRIVATE_KEY_ENV,
    GITHUB_APP_SLUG_ENV,
    GITHUB_API_VERSION,
    IDENTITY_FILENAME,
    GitHubEnvironmentCollectorError,
    GitHubRestReader,
    _mint_github_app_jwt,
    collect_github_environment_identity,
    collect_to_private_directory,
    write_collected_artifacts,
)
from tooling.validate_github_deployment_identity import (
    canonical_digest,
    environment_configuration_digest,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 8, 28, 18, 0, 0, tzinfo=UTC)


def _template() -> dict[str, Any]:
    document = json.loads(
        (
            REPO_ROOT
            / "fixtures/valid/github-deployment-identity-v1-synthetic.json"
        ).read_text(encoding="utf-8")
    )
    document.pop("contract_digest", None)
    document["workflow"].pop("source_sha", None)
    document["environment_protection"]["variables"].pop("MAIN_SHA", None)
    document["contract_digest"] = canonical_digest(document)
    return document


def _paths(template: Mapping[str, Any]) -> dict[str, str]:
    owner = template["repository"]["owner"]
    name = template["repository"]["name"]
    environment = template["workflow"]["github_environment"]
    repository = f"/repos/{owner}/{name}"
    environment_path = f"{repository}/environments/{environment}"
    return {
        "installation": (
            "/app/installations/"
            f"{template['collector_authority']['installation_id']}"
        ),
        "installation_repositories": (
            "/installation/repositories?per_page=100&page=1"
        ),
        "repository": repository,
        "environment": environment_path,
        "branches": (
            f"{environment_path}/deployment-branch-policies?per_page=100&page=1"
        ),
        "custom_protection_rules": (
            f"{environment_path}/deployment_protection_rules?per_page=30&page=1"
        ),
        "environment_variables": f"{environment_path}/variables?per_page=30&page=1",
        "environment_secrets": f"{environment_path}/secrets?per_page=100&page=1",
        "repository_variables": f"{repository}/actions/variables?per_page=30&page=1",
        "organization_variables": (
            f"{repository}/actions/organization-variables?per_page=30&page=1"
        ),
        "repository_secrets": f"{repository}/actions/secrets?per_page=100&page=1",
        "organization_secrets": (
            f"{repository}/actions/organization-secrets?per_page=100&page=1"
        ),
        "oidc": f"{repository}/actions/oidc/customization/sub",
    }


def _responses(template: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    paths = _paths(template)
    variables = template["environment_protection"]["variables"]
    return {
        paths["installation"]: {
            "id": int(template["collector_authority"]["installation_id"]),
            "app_id": int(template["collector_authority"]["app_id"]),
            "app_slug": template["collector_authority"]["app_slug"],
            "repository_selection": "selected",
            "target_type": "Organization",
            "suspended_at": None,
            "permissions": copy.deepcopy(EXPECTED_GITHUB_APP_PERMISSIONS),
            "account": {
                "id": int(template["repository"]["owner_id"]),
                "login": template["repository"]["owner"],
                "type": "Organization",
            },
        },
        paths["installation_repositories"]: {
            "total_count": 1,
            "repositories": [
                {
                    "id": int(template["repository"]["repository_id"]),
                    "name": template["repository"]["name"],
                    "owner": {
                        "id": int(template["repository"]["owner_id"]),
                        "login": template["repository"]["owner"],
                    },
                }
            ],
        },
        paths["repository"]: {
            "id": int(template["repository"]["repository_id"]),
            "name": template["repository"]["name"],
            "visibility": "private",
            "owner": {
                "login": template["repository"]["owner"],
                "id": int(template["repository"]["owner_id"]),
                "type": "Organization",
            },
        },
        paths["environment"]: {
            "id": 7001,
            "name": template["workflow"]["github_environment"],
            "can_admins_bypass": False,
            "protection_rules": [
                {
                    "id": 8001,
                    "type": "required_reviewers",
                    "prevent_self_review": True,
                    "reviewers": [
                        {
                            "type": "User",
                            "reviewer": {
                                "id": 9002,
                                "login": "independent-reviewer",
                                "type": "User",
                            },
                        }
                    ],
                },
                {"id": 8002, "type": "branch_policy"},
            ],
            "deployment_branch_policy": {
                "protected_branches": False,
                "custom_branch_policies": True,
            },
        },
        paths["branches"]: {
            "total_count": 1,
            "branch_policies": [{"id": 8101, "name": "main", "type": "branch"}],
        },
        paths["custom_protection_rules"]: {
            "total_count": 0,
            "custom_deployment_protection_rules": [],
        },
        paths["environment_variables"]: {
            "total_count": len(variables),
            "variables": [
                {"name": key, "value": value}
                for key, value in sorted(variables.items())
            ],
        },
        paths["environment_secrets"]: {
            "total_count": 2,
            "secrets": [
                {"name": "SCANALYZE_GITHUB_ENVIRONMENT_COLLECTOR_PRIVATE_KEY"},
                {"name": "SCANALYZE_LIVE_INPUT_BUNDLE_B64"},
            ],
        },
        paths["repository_variables"]: {"total_count": 0, "variables": []},
        paths["organization_variables"]: {"total_count": 0, "variables": []},
        paths["repository_secrets"]: {"total_count": 0, "secrets": []},
        paths["organization_secrets"]: {"total_count": 0, "secrets": []},
        paths["oidc"]: {
            "use_default": False,
            "include_claim_keys": [
                "repository_owner_id",
                "repository_id",
                "context",
                "workflow_ref",
                "event_name",
            ],
            "use_immutable_subject": False,
        },
    }


class FakeApi:
    def __init__(self, responses: Mapping[str, Mapping[str, Any]]) -> None:
        self.responses = copy.deepcopy(dict(responses))
        self.calls: list[str] = []

    def get(self, path: str) -> Mapping[str, Any]:
        self.calls.append(path)
        if path not in self.responses:
            raise AssertionError(f"unexpected API path: {path}")
        return copy.deepcopy(self.responses[path])


def _collect(
    template: Mapping[str, Any],
    api: FakeApi,
) -> tuple[dict[str, Any], dict[str, Any]]:
    return collect_github_environment_identity(
        identity_template=template,
        fetch_json=api.get,
        fetch_app_json=api.get,
        expected_app_id=template["collector_authority"]["app_id"],
        expected_installation_id=template["collector_authority"]["installation_id"],
        expected_app_slug=template["collector_authority"]["app_slug"],
        secret_transport_proven=True,
        clock=lambda: NOW,
    )


def test_collects_schema_valid_stable_identity_and_ten_minute_anchor() -> None:
    template = _template()
    api = FakeApi(_responses(template))

    identity, anchor = _collect(template, api)

    identity_schema = json.loads(
        (REPO_ROOT / "schemas/github-deployment-identity.v1.schema.json").read_text()
    )
    anchor_schema = json.loads(
        (REPO_ROOT / "schemas/github-environment-anchor.v1.schema.json").read_text()
    )
    jsonschema.Draft202012Validator(identity_schema).validate(identity)
    jsonschema.Draft202012Validator(anchor_schema).validate(anchor)
    assert "source_sha" not in identity["workflow"]
    assert "MAIN_SHA" not in identity["environment_protection"]["variables"]
    assert set(identity["environment_protection"]["variables"]) == set(
        EXPECTED_ENVIRONMENT_VARIABLES
    )
    assert identity["contract_digest"] == canonical_digest(identity)
    assert anchor["configuration_digest"] == environment_configuration_digest(
        identity
    )
    assert anchor["evidence_digest"] == canonical_digest(anchor)
    assert anchor["captured_at"] == "2026-08-28T18:00:00Z"
    assert anchor["expires_at"] == "2026-08-28T18:10:00Z"
    assert identity["environment_protection"]["secret_names"] == [
        "SCANALYZE_GITHUB_ENVIRONMENT_COLLECTOR_PRIVATE_KEY",
        "SCANALYZE_LIVE_INPUT_BUNDLE_B64",
    ]
    assert identity["collector_authority"] == template["collector_authority"]
    assert all(api.calls.count(path) == 2 for path in _paths(template).values())


def test_installation_metadata_uses_app_jwt_not_the_installation_token() -> None:
    template = _template()
    paths = _paths(template)
    responses = _responses(template)
    installation_path = paths["installation"]
    installation_api = FakeApi({installation_path: responses[installation_path]})
    token_api = FakeApi(
        {
            path: response
            for path, response in responses.items()
            if path != installation_path
        }
    )

    collect_github_environment_identity(
        identity_template=template,
        fetch_json=token_api.get,
        fetch_app_json=installation_api.get,
        expected_app_id=template["collector_authority"]["app_id"],
        expected_installation_id=template["collector_authority"][
            "installation_id"
        ],
        expected_app_slug=template["collector_authority"]["app_slug"],
        secret_transport_proven=True,
        clock=lambda: NOW,
    )

    assert installation_api.calls == [installation_path, installation_path]
    assert installation_path not in token_api.calls


@pytest.mark.parametrize(
    ("mutator", "expected_code"),
    [
        (
            lambda responses, paths: responses[paths["environment"]].pop(
                "can_admins_bypass"
            ),
            "GITHUB_ENVIRONMENT_UNSAFE",
        ),
        (
            lambda responses, paths: responses[paths["branches"]][
                "branch_policies"
            ][0].pop("type"),
            "GITHUB_ENVIRONMENT_UNSAFE",
        ),
        (
            lambda responses, paths: responses[paths["oidc"]].pop(
                "include_claim_keys"
            ),
            "GITHUB_OIDC_UNSAFE",
        ),
        (
            lambda responses, paths: responses[
                paths["custom_protection_rules"]
            ].update(
                total_count=1,
                custom_deployment_protection_rules=[{"id": 8801, "enabled": True}],
            ),
            "GITHUB_ENVIRONMENT_UNSAFE",
        ),
    ],
)
def test_missing_or_ambiguous_api_evidence_fails_closed(
    mutator: Any,
    expected_code: str,
) -> None:
    template = _template()
    paths = _paths(template)
    responses = _responses(template)
    mutator(responses, paths)
    responses[paths["environment_variables"]]["total_count"] = len(
        responses[paths["environment_variables"]]["variables"]
    )
    responses[paths["environment_secrets"]]["total_count"] = len(
        responses[paths["environment_secrets"]]["secrets"]
    )

    with pytest.raises(GitHubEnvironmentCollectorError) as error:
        _collect(template, FakeApi(responses))

    assert error.value.code == expected_code


@pytest.mark.parametrize("scope", ["repository_variables", "organization_variables"])
def test_reserved_variable_collision_at_broader_scope_is_denied(scope: str) -> None:
    template = _template()
    paths = _paths(template)
    responses = _responses(template)
    responses[paths[scope]] = {
        "total_count": 1,
        "variables": [{"name": "aws_account_id", "value": "ignored"}],
    }

    with pytest.raises(GitHubEnvironmentCollectorError) as error:
        _collect(template, FakeApi(responses))

    assert error.value.code == "GITHUB_ENVIRONMENT_UNSAFE"


@pytest.mark.parametrize("scope", ["repository_secrets", "organization_secrets"])
def test_reserved_secret_collision_at_broader_scope_is_denied(scope: str) -> None:
    template = _template()
    paths = _paths(template)
    responses = _responses(template)
    responses[paths[scope]] = {
        "total_count": 1,
        "secrets": [{"name": "scanalyze_live_input_bundle_b64"}],
    }

    with pytest.raises(GitHubEnvironmentCollectorError) as error:
        _collect(template, FakeApi(responses))

    assert error.value.code == "GITHUB_ENVIRONMENT_UNSAFE"


def test_broader_scope_variable_values_and_secret_names_are_bound() -> None:
    template = _template()
    paths = _paths(template)
    responses = _responses(template)
    responses[paths["repository_variables"]] = {
        "total_count": 1,
        "variables": [
            {"name": "UNRELATED_REPOSITORY_VARIABLE", "value": "repo-v1"}
        ],
    }
    responses[paths["organization_variables"]] = {
        "total_count": 1,
        "variables": [
            {"name": "UNRELATED_ORGANIZATION_VARIABLE", "value": "org-v1"}
        ],
    }
    responses[paths["repository_secrets"]] = {
        "total_count": 1,
        "secrets": [{"name": "UNRELATED_REPOSITORY_SECRET"}],
    }
    responses[paths["organization_secrets"]] = {
        "total_count": 1,
        "secrets": [{"name": "UNRELATED_ORGANIZATION_SECRET"}],
    }

    identity, _anchor = _collect(template, FakeApi(responses))
    protection = identity["environment_protection"]

    assert protection["repository_variables"] == {
        "UNRELATED_REPOSITORY_VARIABLE": "repo-v1"
    }
    assert protection["effective_organization_variables"] == {
        "UNRELATED_ORGANIZATION_VARIABLE": "org-v1"
    }
    assert protection["repository_secret_names"] == [
        "UNRELATED_REPOSITORY_SECRET"
    ]
    assert protection["effective_organization_secret_names"] == [
        "UNRELATED_ORGANIZATION_SECRET"
    ]


@pytest.mark.parametrize(
    "scope",
    ["repository_variables", "organization_variables"],
)
def test_two_pass_repository_or_effective_org_variable_value_drift_is_denied(
    scope: str,
) -> None:
    template = _template()
    paths = _paths(template)
    responses = _responses(template)
    responses[paths[scope]] = {
        "total_count": 1,
        "variables": [{"name": "UNRELATED_VARIABLE", "value": "first"}],
    }

    class ChangingApi(FakeApi):
        def get(self, path: str) -> Mapping[str, Any]:
            response = copy.deepcopy(super().get(path))
            if path == paths[scope] and self.calls.count(path) == 2:
                response["variables"][0]["value"] = "second"
            return response

    with pytest.raises(GitHubEnvironmentCollectorError) as error:
        _collect(template, ChangingApi(responses))

    assert error.value.code == "GITHUB_CONFIGURATION_UNSTABLE"


@pytest.mark.parametrize(
    "mutator",
    [
        lambda responses, paths: responses[paths["environment_variables"]][
            "variables"
        ].pop(),
        lambda responses, paths: responses[paths["environment_variables"]][
            "variables"
        ].append({"name": "UNEXPECTED", "value": "x"}),
        lambda responses, paths: responses[paths["environment_secrets"]][
            "secrets"
        ].pop(),
    ],
)
def test_exact_environment_inventory_is_required(mutator: Any) -> None:
    template = _template()
    paths = _paths(template)
    responses = _responses(template)
    mutator(responses, paths)
    responses[paths["environment_variables"]]["total_count"] = len(
        responses[paths["environment_variables"]]["variables"]
    )
    responses[paths["environment_secrets"]]["total_count"] = len(
        responses[paths["environment_secrets"]]["secrets"]
    )

    with pytest.raises(GitHubEnvironmentCollectorError):
        _collect(template, FakeApi(responses))


@pytest.mark.parametrize(
    "mutator",
    [
        lambda responses, paths: responses[paths["installation"]].update(
            app_id=7000008
        ),
        lambda responses, paths: responses[paths["installation"]][
            "permissions"
        ].update(contents="write"),
        lambda responses, paths: responses[paths["installation"]][
            "permissions"
        ].pop("secrets"),
        lambda responses, paths: responses[paths["installation_repositories"]][
            "repositories"
        ][0].update(id=2000003),
        lambda responses, paths: responses[paths["installation"]].update(
            suspended_at="2026-08-28T17:00:00Z"
        ),
    ],
)
def test_github_app_identity_installation_scope_and_permissions_are_exact(
    mutator: Any,
) -> None:
    template = _template()
    paths = _paths(template)
    responses = _responses(template)
    mutator(responses, paths)

    with pytest.raises(GitHubEnvironmentCollectorError) as error:
        _collect(template, FakeApi(responses))

    assert error.value.code in {
        "GITHUB_APP_INSTALLATION_INVALID",
        "GITHUB_RESPONSE_INVALID",
    }


def test_private_collection_requires_decoded_transport_and_action_outputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    template = _template()
    template_path = tmp_path / "github-identity-template.json"
    decoded_path = tmp_path / "sealed-request.json"
    template_path.write_text(json.dumps(template), encoding="utf-8")
    decoded_path.write_text(
        json.dumps({"sources": {"github_deployment_identity": template}}),
        encoding="utf-8",
    )
    template_path.chmod(0o600)
    decoded_path.chmod(0o600)
    api = FakeApi(_responses(template))
    monkeypatch.setattr(GitHubRestReader, "get", lambda _self, path: api.get(path))
    monkeypatch.setattr(
        "tooling.github_environment_identity_collector._mint_github_app_jwt",
        lambda *_args, **_kwargs: "short-lived-app-jwt",
    )
    monkeypatch.setenv(DECODED_SECRET_TRANSPORT_PATH_ENV, str(decoded_path))
    monkeypatch.setenv(GITHUB_APP_ID_ENV, template["collector_authority"]["app_id"])
    monkeypatch.setenv(
        GITHUB_APP_INSTALLATION_ID_ENV,
        template["collector_authority"]["installation_id"],
    )
    monkeypatch.setenv(
        GITHUB_APP_SLUG_ENV,
        template["collector_authority"]["app_slug"],
    )
    monkeypatch.setenv(GITHUB_APP_PRIVATE_KEY_ENV, "not-loaded-by-test")

    identity_path, anchor_path = collect_to_private_directory(
        identity_template_path=template_path,
        output_dir=tmp_path / "evidence",
        token="short-lived-job-token",
        clock=lambda: NOW,
    )

    assert identity_path.is_file()
    assert anchor_path.is_file()
    assert all(api.calls.count(path) == 2 for path in _paths(template).values())


def test_private_collection_denies_a_decoded_transport_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    template = _template()
    template_path = tmp_path / "github-identity-template.json"
    decoded_path = tmp_path / "sealed-request.json"
    template_path.write_text(json.dumps(template), encoding="utf-8")
    decoded_path.write_text(
        json.dumps({"sources": {"github_deployment_identity": {}}}),
        encoding="utf-8",
    )
    template_path.chmod(0o600)
    decoded_path.chmod(0o600)
    monkeypatch.setenv(DECODED_SECRET_TRANSPORT_PATH_ENV, str(decoded_path))
    monkeypatch.setenv(GITHUB_APP_ID_ENV, template["collector_authority"]["app_id"])
    monkeypatch.setenv(
        GITHUB_APP_INSTALLATION_ID_ENV,
        template["collector_authority"]["installation_id"],
    )
    monkeypatch.setenv(
        GITHUB_APP_SLUG_ENV,
        template["collector_authority"]["app_slug"],
    )

    with pytest.raises(GitHubEnvironmentCollectorError) as error:
        collect_to_private_directory(
            identity_template_path=template_path,
            output_dir=tmp_path / "evidence",
            token="short-lived-job-token",
            clock=lambda: NOW,
        )

    assert error.value.code == "SECRET_TRANSPORT_UNPROVEN"


def test_decoded_secret_proof_is_required() -> None:
    template = _template()

    with pytest.raises(GitHubEnvironmentCollectorError) as error:
        collect_github_environment_identity(
            identity_template=template,
            fetch_json=FakeApi(_responses(template)).get,
            fetch_app_json=FakeApi(_responses(template)).get,
            expected_app_id=template["collector_authority"]["app_id"],
            expected_installation_id=template["collector_authority"][
                "installation_id"
            ],
            expected_app_slug=template["collector_authority"]["app_slug"],
            secret_transport_proven=False,
            clock=lambda: NOW,
        )

    assert error.value.code == "SECRET_TRANSPORT_UNPROVEN"


def test_two_pass_snapshot_change_is_denied() -> None:
    template = _template()
    paths = _paths(template)
    responses = _responses(template)

    class ChangingApi(FakeApi):
        def get(self, path: str) -> Mapping[str, Any]:
            response = dict(super().get(path))
            if path == paths["environment"] and self.calls.count(path) == 2:
                response = copy.deepcopy(response)
                response["protection_rules"][0]["reviewers"][0]["reviewer"][
                    "id"
                ] = 9003
            return response

    with pytest.raises(GitHubEnvironmentCollectorError) as error:
        _collect(template, ChangingApi(responses))

    assert error.value.code == "GITHUB_CONFIGURATION_UNSTABLE"


def test_outputs_are_create_only_private_files_in_a_new_private_directory(
    tmp_path: Path,
) -> None:
    template = _template()
    identity, anchor = _collect(template, FakeApi(_responses(template)))
    output_dir = tmp_path / "collected"

    identity_path, anchor_path = write_collected_artifacts(
        output_dir=output_dir,
        identity=identity,
        anchor=anchor,
    )

    assert identity_path.name == IDENTITY_FILENAME
    assert anchor_path.name == ANCHOR_FILENAME
    assert stat.S_IMODE(output_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(identity_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(anchor_path.stat().st_mode) == 0o600
    assert json.loads(identity_path.read_text()) == identity
    assert json.loads(anchor_path.read_text()) == anchor
    with pytest.raises(GitHubEnvironmentCollectorError) as error:
        write_collected_artifacts(
            output_dir=output_dir,
            identity=identity,
            anchor=anchor,
        )
    assert error.value.code == "OUTPUT_DIRECTORY_INVALID"


def _decode_base64url(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def test_app_jwt_is_short_lived_rs256_and_bound_to_the_app_id() -> None:
    key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
    private_key = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")

    token = _mint_github_app_jwt(
        private_key,
        app_id="7000007",
        clock=lambda: NOW,
    )

    encoded_header, encoded_payload, encoded_signature = token.split(".")
    header = json.loads(_decode_base64url(encoded_header))
    payload = json.loads(_decode_base64url(encoded_payload))
    assert header == {"alg": "RS256", "typ": "JWT"}
    assert payload == {
        "exp": int(NOW.timestamp()) + 8 * 60,
        "iat": int(NOW.timestamp()) - 60,
        "iss": "7000007",
    }
    key.public_key().verify(
        _decode_base64url(encoded_signature),
        f"{encoded_header}.{encoded_payload}".encode("ascii"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


def test_invalid_app_private_key_fails_with_a_fixed_public_code() -> None:
    private_key = "never-render-this-private-key"

    with pytest.raises(GitHubEnvironmentCollectorError) as error:
        _mint_github_app_jwt(
            private_key,
            app_id="7000007",
            clock=lambda: NOW,
        )

    assert error.value.code == "GITHUB_APP_PRIVATE_KEY_INVALID"
    assert private_key not in str(error.value)


def test_http_reader_uses_exact_get_host_headers_and_never_leaks_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, Any] = {}

    class FakeResponse:
        status = 200

        @staticmethod
        def getheader(name: str) -> str | None:
            return "application/json; charset=utf-8" if name == "Content-Type" else None

        @staticmethod
        def read(_amount: int) -> bytes:
            return b'{"id":1}'

    class FakeConnection:
        def __init__(self, host: str, *, timeout: int) -> None:
            observed["host"] = host
            observed["timeout"] = timeout

        @staticmethod
        def request(
            method: str,
            path: str,
            *,
            headers: Mapping[str, str],
        ) -> None:
            observed["method"] = method
            observed["path"] = path
            observed["headers"] = dict(headers)

        @staticmethod
        def getresponse() -> FakeResponse:
            return FakeResponse()

        @staticmethod
        def close() -> None:
            return None

    monkeypatch.setattr(
        "tooling.github_environment_identity_collector.http.client.HTTPSConnection",
        FakeConnection,
    )
    token = "not-a-real-token"

    assert GitHubRestReader(token).get("/repos/owner/repository") == {"id": 1}
    assert observed["host"] == "api.github.com"
    assert observed["method"] == "GET"
    assert observed["path"] == "/repos/owner/repository"
    assert observed["headers"]["X-GitHub-Api-Version"] == GITHUB_API_VERSION
    assert observed["headers"]["Authorization"] == f"Bearer {token}"

    assert GitHubRestReader(
        token,
        app_installation_id="42",
    ).get("/app/installations/42") == {"id": 1}
    assert observed["path"] == "/app/installations/42"


def test_http_failure_exposes_only_a_fixed_error_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class DeniedResponse:
        status = 403

    class DeniedConnection:
        def __init__(self, _host: str, *, timeout: int) -> None:
            assert timeout == 10

        @staticmethod
        def request(*_args: Any, **_kwargs: Any) -> None:
            return None

        @staticmethod
        def getresponse() -> DeniedResponse:
            return DeniedResponse()

        @staticmethod
        def close() -> None:
            return None

    monkeypatch.setattr(
        "tooling.github_environment_identity_collector.http.client.HTTPSConnection",
        DeniedConnection,
    )
    token = "never-render-this-token"

    with pytest.raises(GitHubEnvironmentCollectorError) as error:
        GitHubRestReader(token).get("/repos/owner/repository")

    assert error.value.code == "GITHUB_READ_FAILED"
    assert token not in str(error.value)


@pytest.mark.parametrize(
    "path",
    [
        "/app",
        "/user",
        "/installation",
        "/installation/repositories",
        "/app/installations/42",
    ],
)
def test_http_reader_refuses_non_inventory_selectors(path: str) -> None:
    with pytest.raises(GitHubEnvironmentCollectorError) as error:
        GitHubRestReader("short-lived-job-token").get(path)

    assert error.value.code == "GITHUB_SELECTOR_INVALID"


def test_app_jwt_reader_refuses_every_selector_except_its_installation() -> None:
    reader = GitHubRestReader(
        "short-lived-app-jwt",
        app_installation_id="42",
    )

    for path in (
        "/app/installations/41",
        "/installation/repositories?per_page=100&page=1",
        "/repos/owner/repository",
    ):
        with pytest.raises(GitHubEnvironmentCollectorError) as error:
            reader.get(path)
        assert error.value.code == "GITHUB_SELECTOR_INVALID"


def test_naive_collection_time_is_denied() -> None:
    template = _template()
    with pytest.raises(GitHubEnvironmentCollectorError) as error:
        collect_github_environment_identity(
            identity_template=template,
            fetch_json=FakeApi(_responses(template)).get,
            fetch_app_json=FakeApi(_responses(template)).get,
            expected_app_id=template["collector_authority"]["app_id"],
            expected_installation_id=template["collector_authority"][
                "installation_id"
            ],
            expected_app_slug=template["collector_authority"]["app_slug"],
            secret_transport_proven=True,
            clock=lambda: datetime(2026, 8, 28, 18, 0, 0),
        )
    assert error.value.code == "COLLECTION_TIME_INVALID"
