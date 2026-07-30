"""Fail-closed effective-IAM verifier for the GUG-221 repair broker.

The broker must not trust the CloudFormation template or a prior deployment
receipt as evidence of its current authority.  This module reads the six live
roles that form the server-side PEP, renders their reviewed policy templates
with the immutable broker bindings, and returns a snapshot only when the live
trust and permissions are exactly those reviewed artifacts.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import unquote

try:  # Support package-style Lambda imports and direct tooling imports.
    from .platform_authority_lambda_audit_repair_broker import (
        AUTHORITY_ACCOUNT_ID,
        MANAGEMENT_ACCOUNT_ID,
        BrokerConfig,
        BrokerContractError,
        canonical_digest,
    )
except ImportError:  # pragma: no cover - deployment entrypoint compatibility.
    from platform_authority_lambda_audit_repair_broker import (  # type: ignore
        AUTHORITY_ACCOUNT_ID,
        MANAGEMENT_ACCOUNT_ID,
        BrokerConfig,
        BrokerContractError,
        canonical_digest,
    )


AUTHORITY_REPAIR_POLICY_PATH = Path(
    "policies/iam/"
    "platform-authority-lambda-audit-repair-authority-execution-role.json"
)
AUTHORITY_PLAN_POLICY_PATH = Path(
    "policies/iam/"
    "platform-authority-lambda-audit-plan-authority-execution-role.json"
)
AUTHORITY_RECONCILE_POLICY_PATH = Path(
    "policies/iam/"
    "platform-authority-lambda-audit-reconcile-authority-execution-role.json"
)
AUTHORITY_INVOCATION_INSPECTOR_POLICY_PATH = Path(
    "policies/iam/"
    "platform-authority-lambda-audit-repair-invocation-inspector-role.json"
)
MANAGEMENT_MUTATION_POLICY_PATH = Path(
    "policies/iam/"
    "platform-authority-lambda-audit-repair-mutation-service-role.json"
)
MANAGEMENT_READBACK_POLICY_PATH = Path(
    "policies/iam/"
    "platform-authority-lambda-audit-repair-readback-service-role.json"
)

PLAN_EXECUTION_ROLE_NAME = "ScanalyzeLambdaAuditRepairPlan"
REPAIR_EXECUTION_ROLE_NAME = "ScanalyzeLambdaAuditRepairExecution"
RECONCILE_EXECUTION_ROLE_NAME = "ScanalyzeLambdaAuditRepairReconcile"
INVOCATION_INSPECTOR_ROLE_NAME = (
    "ScanalyzeLambdaAuditRepairAuthorityInspector"
)
MUTATION_SERVICE_ROLE_NAME = "ScanalyzeLambdaAuditRepairMutationServiceRole"
READBACK_SERVICE_ROLE_NAME = "ScanalyzeLambdaAuditRepairReadbackServiceRole"
AUTHORITY_ROLE_PATH = "/"
AUTHORITY_INSPECTOR_ROLE_PATH = "/scanalyze/platform-authority/"
MANAGEMENT_ROLE_PATH = "/scanalyze/platform-authority/"
PLAN_EXECUTION_POLICY_NAME = "Gug221ReadOnlyPlanAndLedgerCreation"
REPAIR_EXECUTION_POLICY_NAME = "Gug221RepairExecution"
RECONCILE_EXECUTION_POLICY_NAME = "Gug221ReadOnlyReconciliation"
INVOCATION_INSPECTOR_POLICY_NAME = "Gug221InvocationAuthorityInspection"
MUTATION_SERVICE_POLICY_NAME = "Gug221ExactRepairMutations"
READBACK_SERVICE_POLICY_NAME = "Gug221ExactReadback"
MAX_SESSION_DURATION_SECONDS = 3600


class IamEffectiveVerifierPort(Protocol):
    """Runtime port used by each pre-effect and final broker snapshot."""

    def snapshot(self, config: BrokerConfig) -> "IamEffectiveSnapshot": ...


@dataclass(frozen=True)
class ExpectedIamRole:
    """Reviewed role contract after immutable placeholders are rendered."""

    account_id: str
    role_name: str
    path: str
    arn: str
    trust_policy: Mapping[str, Any]
    inline_policy_name: str
    inline_policy: Mapping[str, Any]

    @property
    def trust_policy_digest(self) -> str:
        return canonical_digest(self.trust_policy)

    @property
    def inline_policy_digest(self) -> str:
        return canonical_digest(self.inline_policy)


@dataclass(frozen=True)
class IamRoleSnapshot:
    account_id: str
    role_name: str
    path: str
    arn: str
    max_session_duration: int
    trust_policy_digest: str
    inline_policy_name: str
    inline_policy_digest: str
    attached_managed_policy_arns: tuple[str, ...]
    permissions_boundary_arn: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "account_id": self.account_id,
            "role_name": self.role_name,
            "path": self.path,
            "arn": self.arn,
            "max_session_duration": self.max_session_duration,
            "trust_policy_digest": self.trust_policy_digest,
            "inline_policy_name": self.inline_policy_name,
            "inline_policy_digest": self.inline_policy_digest,
            "attached_managed_policy_arns": list(
                self.attached_managed_policy_arns
            ),
            "permissions_boundary_arn": self.permissions_boundary_arn,
        }


@dataclass(frozen=True)
class IamEffectiveSnapshot:
    authority_roles: tuple[IamRoleSnapshot, ...]
    management_roles: tuple[IamRoleSnapshot, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "authority_roles": [item.as_dict() for item in self.authority_roles],
            "management_roles": [item.as_dict() for item in self.management_roles],
        }

    def digest(self) -> str:
        return canonical_digest(self.as_dict())


def _duplicate_rejecting_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BrokerContractError(
                "IAM_POLICY_MALFORMED", "IAM policy contains duplicate keys"
            )
        result[key] = value
    return result


def _strict_json_object(value: Any, *, code: str) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        normalized = dict(value)
        def validate_json(item: Any) -> None:
            if isinstance(item, Mapping):
                if any(not isinstance(key, str) for key in item):
                    raise BrokerContractError(
                        code, "IAM policy contains a non-string key"
                    )
                for nested in item.values():
                    validate_json(nested)
                return
            if isinstance(item, list):
                for nested in item:
                    validate_json(nested)
                return
            if item is None or type(item) in {str, bool, int, float}:
                return
            raise BrokerContractError(code, "IAM policy contains a non-JSON value")

        validate_json(normalized)
        try:
            # Round-trip provider mappings so nested non-JSON values cannot be
            # silently accepted by the canonical digest.
            encoded = json.dumps(normalized, ensure_ascii=False, allow_nan=False)
            parsed = json.loads(
                encoded, object_pairs_hook=_duplicate_rejecting_object
            )
        except (TypeError, ValueError) as exc:
            raise BrokerContractError(code, "IAM policy is not strict JSON") from exc
    elif isinstance(value, str) and value:
        try:
            parsed = json.loads(
                unquote(value), object_pairs_hook=_duplicate_rejecting_object
            )
        except (json.JSONDecodeError, BrokerContractError) as exc:
            if isinstance(exc, BrokerContractError):
                raise
            raise BrokerContractError(code, "IAM policy is malformed") from exc
    else:
        raise BrokerContractError(code, "IAM policy must be a JSON object")
    if not isinstance(parsed, dict):
        raise BrokerContractError(code, "IAM policy must be a JSON object")
    return parsed


def _load_policy_template(repo_root: Path, relative_path: Path) -> Mapping[str, Any]:
    try:
        root = repo_root.resolve(strict=True)
        unresolved = root / relative_path
        if unresolved.is_symlink():
            raise BrokerContractError(
                "IAM_POLICY_ARTIFACT_UNAVAILABLE",
                "reviewed IAM policy artifact is unsafe",
            )
        candidate = unresolved.resolve(strict=True)
        candidate.relative_to(root)
    except BrokerContractError:
        raise
    except (OSError, ValueError) as exc:
        raise BrokerContractError(
            "IAM_POLICY_ARTIFACT_UNAVAILABLE",
            "reviewed IAM policy artifact is unavailable",
        ) from exc
    if not candidate.is_file():
        raise BrokerContractError(
            "IAM_POLICY_ARTIFACT_UNAVAILABLE",
            "reviewed IAM policy artifact is unsafe",
        )
    try:
        raw = candidate.read_text(encoding="utf-8")
    except OSError as exc:
        raise BrokerContractError(
            "IAM_POLICY_ARTIFACT_UNAVAILABLE",
            "reviewed IAM policy artifact is unreadable",
        ) from exc
    return _strict_json_object(raw, code="IAM_POLICY_ARTIFACT_MALFORMED")


def _render_value(value: Any, replacements: Mapping[str, str]) -> Any:
    if isinstance(value, str):
        rendered = value
        for name, replacement in replacements.items():
            rendered = rendered.replace("${" + name + "}", replacement)
        if "${" in rendered:
            raise BrokerContractError(
                "IAM_POLICY_BINDING_INCOMPLETE",
                "reviewed IAM policy retains an unbound placeholder",
            )
        return rendered
    if isinstance(value, list):
        return [_render_value(item, replacements) for item in value]
    if isinstance(value, dict):
        return {
            key: _render_value(item, replacements)
            for key, item in value.items()
        }
    if value is None or type(value) in {bool, int, float}:
        return value
    raise BrokerContractError(
        "IAM_POLICY_ARTIFACT_MALFORMED",
        "reviewed IAM policy contains a non-JSON value",
    )


def _render_policy(
    template: Mapping[str, Any],
    replacements: Mapping[str, str],
    *,
    omit_identity_center_kms: bool = False,
) -> Mapping[str, Any]:
    rendered = _render_value(dict(template), replacements)
    if not isinstance(rendered, dict):  # Defensive; template is already an object.
        raise BrokerContractError(
            "IAM_POLICY_ARTIFACT_MALFORMED", "rendered IAM policy is malformed"
        )
    statements = rendered.get("Statement")
    if not isinstance(statements, list):
        raise BrokerContractError(
            "IAM_POLICY_ARTIFACT_MALFORMED", "reviewed IAM policy has no statements"
        )
    if omit_identity_center_kms:
        omitted = {
            "DecryptOnlyThroughExactIdentityCenterInstance",
            "DecryptOnlyThroughExactIdentityStore",
        }
        rendered["Statement"] = [
            statement
            for statement in statements
            if not isinstance(statement, Mapping)
            or statement.get("Sid") not in omitted
        ]
    return rendered


def _lambda_trust() -> Mapping[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "LambdaServiceOnly",
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }


def _management_trust(
    *, sid: str, execution_role_arns: tuple[str, ...]
) -> Mapping[str, Any]:
    if not execution_role_arns:
        raise BrokerContractError(
            "IAM_TRUST_BINDING_MISSING",
            "management trust requires at least one execution role",
        )
    principal_binding: str | list[str]
    if len(execution_role_arns) == 1:
        principal_binding = execution_role_arns[0]
    else:
        principal_binding = list(execution_role_arns)
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": sid,
                "Effect": "Allow",
                "Principal": {
                    "AWS": f"arn:aws:iam::{AUTHORITY_ACCOUNT_ID}:root"
                },
                "Action": ["sts:AssumeRole", "sts:SetSourceIdentity"],
                "Condition": {
                    "StringEquals": {
                        "aws:PrincipalAccount": AUTHORITY_ACCOUNT_ID
                    },
                    "ArnEquals": {"aws:PrincipalArn": principal_binding},
                },
            }
        ],
    }


def expected_role_specs(
    config: BrokerConfig,
    *,
    repo_root: Path | None = None,
    policy_loader: Callable[[Path], Mapping[str, Any]] | None = None,
) -> tuple[ExpectedIamRole, ...]:
    """Render the six reviewed live-role contracts for ``config``."""

    root = repo_root or Path.cwd()
    load_policy = policy_loader or (lambda path: _load_policy_template(root, path))
    plan_execution_arn = (
        f"arn:aws:iam::{AUTHORITY_ACCOUNT_ID}:role/{PLAN_EXECUTION_ROLE_NAME}"
    )
    repair_execution_arn = (
        f"arn:aws:iam::{AUTHORITY_ACCOUNT_ID}:role/{REPAIR_EXECUTION_ROLE_NAME}"
    )
    reconcile_execution_arn = (
        f"arn:aws:iam::{AUTHORITY_ACCOUNT_ID}:role/"
        f"{RECONCILE_EXECUTION_ROLE_NAME}"
    )
    invocation_inspector_arn = (
        f"arn:aws:iam::{AUTHORITY_ACCOUNT_ID}:role"
        f"{AUTHORITY_INSPECTOR_ROLE_PATH}{INVOCATION_INSPECTOR_ROLE_NAME}"
    )
    mutation_arn = (
        f"arn:aws:iam::{MANAGEMENT_ACCOUNT_ID}:role"
        f"{MANAGEMENT_ROLE_PATH}{MUTATION_SERVICE_ROLE_NAME}"
    )
    readback_arn = (
        f"arn:aws:iam::{MANAGEMENT_ACCOUNT_ID}:role"
        f"{MANAGEMENT_ROLE_PATH}{READBACK_SERVICE_ROLE_NAME}"
    )
    authority_replacements = {
        "repair_id": config.repair_id,
        "code_signing_config_arn": config.expected_code_signing_config_arn,
        "repair_ledger_kms_key_arn": config.repair_ledger_kms_key_arn,
        "aws_partition": "aws",
        "authority_account_id": AUTHORITY_ACCOUNT_ID,
        "region": "us-east-1",
    }
    identity_store_arn = (
        f"arn:aws:identitystore::{MANAGEMENT_ACCOUNT_ID}:identitystore/"
        f"{config.identity_store_id}"
    )
    principal_arn = f"arn:aws:identitystore:::user/{config.principal_id}"
    management_replacements = {
        "identity_center_instance_arn": config.instance_arn,
        "collector_permission_set_arn": config.collector_permission_set_arn,
        "repair_invoker_permission_set_arn": (
            config.repair_invoker_permission_set_arn
        ),
        "identity_store_arn": identity_store_arn,
        "repair_principal_user_arn": principal_arn,
        "identity_center_kms_key_arn": config.identity_center_kms_key_arn or "",
    }
    omit_kms = config.identity_center_kms_mode == "AWS_OWNED_KMS_KEY"
    return (
        ExpectedIamRole(
            account_id=AUTHORITY_ACCOUNT_ID,
            role_name=PLAN_EXECUTION_ROLE_NAME,
            path=AUTHORITY_ROLE_PATH,
            arn=plan_execution_arn,
            trust_policy=_lambda_trust(),
            inline_policy_name=PLAN_EXECUTION_POLICY_NAME,
            inline_policy=_render_policy(
                load_policy(AUTHORITY_PLAN_POLICY_PATH),
                authority_replacements,
            ),
        ),
        ExpectedIamRole(
            account_id=AUTHORITY_ACCOUNT_ID,
            role_name=REPAIR_EXECUTION_ROLE_NAME,
            path=AUTHORITY_ROLE_PATH,
            arn=repair_execution_arn,
            trust_policy=_lambda_trust(),
            inline_policy_name=REPAIR_EXECUTION_POLICY_NAME,
            inline_policy=_render_policy(
                load_policy(AUTHORITY_REPAIR_POLICY_PATH),
                authority_replacements,
            ),
        ),
        ExpectedIamRole(
            account_id=AUTHORITY_ACCOUNT_ID,
            role_name=RECONCILE_EXECUTION_ROLE_NAME,
            path=AUTHORITY_ROLE_PATH,
            arn=reconcile_execution_arn,
            trust_policy=_lambda_trust(),
            inline_policy_name=RECONCILE_EXECUTION_POLICY_NAME,
            inline_policy=_render_policy(
                load_policy(AUTHORITY_RECONCILE_POLICY_PATH),
                authority_replacements,
            ),
        ),
        ExpectedIamRole(
            account_id=AUTHORITY_ACCOUNT_ID,
            role_name=INVOCATION_INSPECTOR_ROLE_NAME,
            path=AUTHORITY_INSPECTOR_ROLE_PATH,
            arn=invocation_inspector_arn,
            trust_policy=_management_trust(
                sid="AssumeOnlyFromExactGug221ExecutionRoles",
                execution_role_arns=(
                    plan_execution_arn,
                    repair_execution_arn,
                    reconcile_execution_arn,
                ),
            ),
            inline_policy_name=INVOCATION_INSPECTOR_POLICY_NAME,
            inline_policy=_render_policy(
                load_policy(AUTHORITY_INVOCATION_INSPECTOR_POLICY_PATH),
                authority_replacements,
            ),
        ),
        ExpectedIamRole(
            account_id=MANAGEMENT_ACCOUNT_ID,
            role_name=MUTATION_SERVICE_ROLE_NAME,
            path=MANAGEMENT_ROLE_PATH,
            arn=mutation_arn,
            trust_policy=_management_trust(
                sid="AssumeOnlyFromExactRepairLambdaRole",
                execution_role_arns=(repair_execution_arn,),
            ),
            inline_policy_name=MUTATION_SERVICE_POLICY_NAME,
            inline_policy=_render_policy(
                load_policy(MANAGEMENT_MUTATION_POLICY_PATH),
                management_replacements,
                omit_identity_center_kms=omit_kms,
            ),
        ),
        ExpectedIamRole(
            account_id=MANAGEMENT_ACCOUNT_ID,
            role_name=READBACK_SERVICE_ROLE_NAME,
            path=MANAGEMENT_ROLE_PATH,
            arn=readback_arn,
            trust_policy=_management_trust(
                sid="AssumeOnlyFromExactPlanOrReconcileLambdaRoles",
                execution_role_arns=(plan_execution_arn, reconcile_execution_arn),
            ),
            inline_policy_name=READBACK_SERVICE_POLICY_NAME,
            inline_policy=_render_policy(
                load_policy(MANAGEMENT_READBACK_POLICY_PATH),
                management_replacements,
                omit_identity_center_kms=omit_kms,
            ),
        ),
    )


def validate_iam_effective_snapshot(
    config: BrokerConfig,
    snapshot: IamEffectiveSnapshot,
    *,
    repo_root: Path | None = None,
) -> None:
    """Validate even snapshots supplied by a test or alternate adapter."""

    specs = expected_role_specs(config, repo_root=repo_root)
    expected = tuple(
        IamRoleSnapshot(
            account_id=spec.account_id,
            role_name=spec.role_name,
            path=spec.path,
            arn=spec.arn,
            max_session_duration=MAX_SESSION_DURATION_SECONDS,
            trust_policy_digest=spec.trust_policy_digest,
            inline_policy_name=spec.inline_policy_name,
            inline_policy_digest=spec.inline_policy_digest,
            attached_managed_policy_arns=(),
            permissions_boundary_arn=None,
        )
        for spec in specs
    )
    if snapshot.authority_roles != expected[:4]:
        raise BrokerContractError(
            "AUTHORITY_IAM_SNAPSHOT_MISMATCH",
            "authority execution-role IAM snapshot differs",
        )
    if snapshot.management_roles != expected[4:]:
        raise BrokerContractError(
            "MANAGEMENT_IAM_SNAPSHOT_MISMATCH",
            "management service-role IAM snapshot differs",
        )


class AwsIamEffectiveVerifier:
    """Read and verify exact authority- and management-account role state."""

    def __init__(
        self,
        *,
        authority_iam: Any,
        management_iam: Any,
        repo_root: Path | None = None,
    ) -> None:
        self._authority_iam = authority_iam
        self._management_iam = management_iam
        self._repo_root = repo_root or Path.cwd()

    @staticmethod
    def _call(client: Any, method_name: str, **kwargs: Any) -> Mapping[str, Any]:
        try:
            response = getattr(client, method_name)(**kwargs)
        except BrokerContractError:
            raise
        except Exception as exc:
            raise BrokerContractError(
                "IAM_PROVIDER_FAILURE", "effective IAM readback failed"
            ) from exc
        if not isinstance(response, Mapping):
            raise BrokerContractError(
                "IAM_PROVIDER_RESPONSE_MALFORMED",
                "effective IAM response must be an object",
            )
        return response

    def _paginate(
        self,
        client: Any,
        method_name: str,
        result_key: str,
        **kwargs: Any,
    ) -> list[Any]:
        values: list[Any] = []
        marker: str | None = None
        seen_markers: set[str] = set()
        for _ in range(100):
            call_kwargs = dict(kwargs)
            if marker is not None:
                call_kwargs["Marker"] = marker
            response = self._call(client, method_name, **call_kwargs)
            page = response.get(result_key)
            if not isinstance(page, list):
                raise BrokerContractError(
                    "IAM_PROVIDER_RESPONSE_MALFORMED",
                    "effective IAM inventory page is malformed",
                )
            values.extend(page)
            truncated = response.get("IsTruncated")
            next_marker = response.get("Marker")
            if type(truncated) is not bool:
                raise BrokerContractError(
                    "IAM_PROVIDER_RESPONSE_MALFORMED",
                    "effective IAM pagination state is malformed",
                )
            if not truncated:
                if next_marker is not None:
                    raise BrokerContractError(
                        "IAM_PROVIDER_RESPONSE_MALFORMED",
                        "terminal effective IAM page carries a marker",
                    )
                return values
            if not isinstance(next_marker, str) or not next_marker:
                raise BrokerContractError(
                    "IAM_PROVIDER_RESPONSE_MALFORMED",
                    "effective IAM pagination marker is malformed",
                )
            if next_marker in seen_markers:
                raise BrokerContractError(
                    "IAM_PAGINATION_CYCLE",
                    "effective IAM pagination repeated a marker",
                )
            seen_markers.add(next_marker)
            marker = next_marker
        raise BrokerContractError(
            "IAM_PAGINATION_LIMIT",
            "effective IAM inventory exceeded the page limit",
        )

    def _read_role(self, client: Any, spec: ExpectedIamRole) -> IamRoleSnapshot:
        response = self._call(client, "get_role", RoleName=spec.role_name)
        role = response.get("Role")
        if not isinstance(role, Mapping):
            raise BrokerContractError(
                "IAM_ROLE_READBACK_MALFORMED", "effective IAM role is malformed"
            )
        if (
            role.get("RoleName") != spec.role_name
            or role.get("Path") != spec.path
            or role.get("Arn") != spec.arn
        ):
            raise BrokerContractError(
                "IAM_ROLE_BINDING_MISMATCH", "effective IAM role binding differs"
            )
        if role.get("MaxSessionDuration") != MAX_SESSION_DURATION_SECONDS:
            raise BrokerContractError(
                "IAM_ROLE_SESSION_MISMATCH",
                "effective IAM role session duration differs",
            )
        boundary = role.get("PermissionsBoundary")
        if boundary is not None:
            raise BrokerContractError(
                "IAM_ROLE_BOUNDARY_PRESENT",
                "effective IAM role has a permissions boundary",
            )
        trust = _strict_json_object(
            role.get("AssumeRolePolicyDocument"), code="IAM_TRUST_MALFORMED"
        )
        if trust != spec.trust_policy:
            raise BrokerContractError(
                "IAM_TRUST_MISMATCH", "effective IAM trust differs"
            )

        attached = self._paginate(
            client,
            "list_attached_role_policies",
            "AttachedPolicies",
            RoleName=spec.role_name,
        )
        if any(
            not isinstance(item, Mapping)
            or not isinstance(item.get("PolicyName"), str)
            or not item.get("PolicyName")
            or not isinstance(item.get("PolicyArn"), str)
            or not item.get("PolicyArn")
            for item in attached
        ):
            raise BrokerContractError(
                "IAM_MANAGED_POLICY_INVENTORY_MALFORMED",
                "managed-policy inventory is malformed",
            )
        attached_arns = tuple(sorted(item["PolicyArn"] for item in attached))
        if len(attached_arns) != len(set(attached_arns)):
            raise BrokerContractError(
                "IAM_MANAGED_POLICY_INVENTORY_DUPLICATE",
                "managed-policy inventory has duplicates",
            )
        if attached_arns:
            raise BrokerContractError(
                "IAM_MANAGED_POLICY_PRESENT",
                "effective IAM role has a managed-policy attachment",
            )

        inline_names_raw = self._paginate(
            client,
            "list_role_policies",
            "PolicyNames",
            RoleName=spec.role_name,
        )
        if any(not isinstance(name, str) or not name for name in inline_names_raw):
            raise BrokerContractError(
                "IAM_INLINE_POLICY_INVENTORY_MALFORMED",
                "inline-policy inventory is malformed",
            )
        inline_names = tuple(sorted(inline_names_raw))
        if len(inline_names) != len(set(inline_names)):
            raise BrokerContractError(
                "IAM_INLINE_POLICY_INVENTORY_DUPLICATE",
                "inline-policy inventory has duplicates",
            )
        if inline_names != (spec.inline_policy_name,):
            raise BrokerContractError(
                "IAM_INLINE_POLICY_SET_MISMATCH",
                "effective IAM inline-policy names differ",
            )
        policy_response = self._call(
            client,
            "get_role_policy",
            RoleName=spec.role_name,
            PolicyName=spec.inline_policy_name,
        )
        if (
            policy_response.get("RoleName") != spec.role_name
            or policy_response.get("PolicyName") != spec.inline_policy_name
        ):
            raise BrokerContractError(
                "IAM_INLINE_POLICY_BINDING_MISMATCH",
                "effective IAM inline-policy binding differs",
            )
        policy = _strict_json_object(
            policy_response.get("PolicyDocument"),
            code="IAM_INLINE_POLICY_MALFORMED",
        )
        if policy != spec.inline_policy:
            raise BrokerContractError(
                "IAM_INLINE_POLICY_MISMATCH",
                "effective IAM inline policy differs from the reviewed artifact",
            )
        return IamRoleSnapshot(
            account_id=spec.account_id,
            role_name=spec.role_name,
            path=spec.path,
            arn=spec.arn,
            max_session_duration=MAX_SESSION_DURATION_SECONDS,
            trust_policy_digest=spec.trust_policy_digest,
            inline_policy_name=spec.inline_policy_name,
            inline_policy_digest=spec.inline_policy_digest,
            attached_managed_policy_arns=(),
            permissions_boundary_arn=None,
        )

    def snapshot(self, config: BrokerConfig) -> IamEffectiveSnapshot:
        specs = expected_role_specs(config, repo_root=self._repo_root)
        observed = IamEffectiveSnapshot(
            authority_roles=tuple(
                self._read_role(self._authority_iam, spec) for spec in specs[:4]
            ),
            management_roles=tuple(
                self._read_role(self._management_iam, spec) for spec in specs[4:]
            ),
        )
        validate_iam_effective_snapshot(
            config, observed, repo_root=self._repo_root
        )
        return observed
