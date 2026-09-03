"""Exact effective-IAM gate for the GUG-376 Plan permission repair PEP.

The gate reads all six roles that participate in the protected execution path
on every invocation.  Role identities, trust-policy digests, inline-policy
names and normalized policy digests come from one reviewed, checked-in control
artifact.  Live state and Lambda environment values can bind placeholders, but
they cannot declare the expected authority shape.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any, Mapping
from urllib.parse import unquote

try:  # Support package-style Lambda imports and direct tooling imports.
    from .platform_authority_plan_permission_repair import (
        PlanPermissionRepairError,
        digest_value,
    )
except ImportError:  # pragma: no cover - deployment entrypoint compatibility.
    from platform_authority_plan_permission_repair import (  # type: ignore
        PlanPermissionRepairError,
        digest_value,
    )


AUTHORITY_ACCOUNT_ID = "042360977644"
MANAGEMENT_ACCOUNT_ID = "839393571433"
CONTROL_PATH = Path(
    "governance/platform-authority-bootstrap-plan-repair-effective-iam.json"
)
CONTROL_ID = (
    "scanalyze.platform_authority.bootstrap_plan_repair_effective_iam.v1"
)
KMS_MODES = frozenset({"AWS_OWNED_KMS_KEY", "CUSTOMER_MANAGED_KEY"})
MAX_IAM_PAGES = 100
MAX_IAM_ITEMS = 1_000

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REPAIR_ID = re.compile(r"^gug376-plan-permission-repair-[0-9a-f]{64}$")
_INSTANCE_ARN = re.compile(
    r"^arn:aws:sso:::instance/ssoins-[A-Za-z0-9]{16}$"
)
_PERMISSION_SET_ARN = re.compile(
    r"^arn:aws:sso:::permissionSet/ssoins-[A-Za-z0-9]{16}/"
    r"ps-[A-Za-z0-9]{16}$"
)
_IDENTITY_STORE_ID = re.compile(r"^d-[a-z0-9]{10,}$")
_PRINCIPAL_ID = re.compile(
    r"^(?:[0-9a-f]{10}-)?[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$"
)
_LEDGER_KMS_ARN = re.compile(
    r"^arn:aws:kms:us-east-1:042360977644:key/"
    r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$"
)
_IDENTITY_CENTER_KMS_ARN = re.compile(
    r"^arn:aws:kms:us-east-1:839393571433:key/"
    r"(?:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}|"
    r"mrk-[0-9a-f]{32})$"
)
_CODE_SIGNING_CONFIG_ARN = re.compile(
    r"^arn:aws:lambda:us-east-1:042360977644:"
    r"code-signing-config:csc-[a-z0-9]{17}$"
)

_ROLE_IDENTITIES = (
    (
        "PlanExecutionRole",
        AUTHORITY_ACCOUNT_ID,
        "ScanalyzeBootstrapPlanRepairPlan",
        "/",
        "Gug376ReadOnlyPlanAndLedgerCreation",
    ),
    (
        "RepairExecutionRole",
        AUTHORITY_ACCOUNT_ID,
        "ScanalyzeBootstrapPlanRepairExecution",
        "/",
        "Gug376OneShotPlanPolicyRepair",
    ),
    (
        "ReconcileExecutionRole",
        AUTHORITY_ACCOUNT_ID,
        "ScanalyzeBootstrapPlanRepairReconcile",
        "/",
        "Gug376ReconcileAndAttest",
    ),
    (
        "InvocationAuthorityInspectorRole",
        AUTHORITY_ACCOUNT_ID,
        "ScanalyzeBootstrapPlanRepairInspector",
        "/scanalyze/platform-authority/",
        "Gug376ReadOnlyInvocationAuthorityInventory",
    ),
    (
        "MutationServiceRole",
        MANAGEMENT_ACCOUNT_ID,
        "ScanalyzeBootstrapPlanRepairMutation",
        "/scanalyze/platform-authority/",
        "Gug376ExactPlanPolicyRepairMutations",
    ),
    (
        "ReadbackServiceRole",
        MANAGEMENT_ACCOUNT_ID,
        "ScanalyzeBootstrapPlanRepairReadback",
        "/scanalyze/platform-authority/",
        "Gug376ExactPlanPolicyRepairReadback",
    ),
)


@dataclass(frozen=True, slots=True)
class PlanRepairIamBindings:
    """Immutable runtime values allowed to render reviewed policy controls."""

    repair_id: str
    code_signing_config_arn: str
    repair_ledger_kms_key_arn: str
    identity_center_instance_arn: str
    plan_permission_set_arn: str
    repair_invoker_permission_set_arn: str
    identity_store_id: str
    repair_principal_id: str
    identity_center_kms_mode: str
    identity_center_kms_key_arn: str | None

    def __post_init__(self) -> None:
        checks = (
            (_REPAIR_ID, self.repair_id),
            (_CODE_SIGNING_CONFIG_ARN, self.code_signing_config_arn),
            (_LEDGER_KMS_ARN, self.repair_ledger_kms_key_arn),
            (_INSTANCE_ARN, self.identity_center_instance_arn),
            (_PERMISSION_SET_ARN, self.plan_permission_set_arn),
            (_PERMISSION_SET_ARN, self.repair_invoker_permission_set_arn),
            (_IDENTITY_STORE_ID, self.identity_store_id),
            (_PRINCIPAL_ID, self.repair_principal_id),
        )
        if any(pattern.fullmatch(value) is None for pattern, value in checks):
            raise PlanPermissionRepairError(
                "IAM_BINDING_MALFORMED",
                "effective-IAM binding is malformed",
            )
        if self.plan_permission_set_arn == self.repair_invoker_permission_set_arn:
            raise PlanPermissionRepairError(
                "IAM_BINDING_COLLISION",
                "effective-IAM permission-set bindings collide",
            )
        if self.identity_center_kms_mode not in KMS_MODES:
            raise PlanPermissionRepairError(
                "IAM_BINDING_MALFORMED",
                "effective-IAM KMS mode is malformed",
            )
        if self.identity_center_kms_mode == "AWS_OWNED_KMS_KEY":
            if self.identity_center_kms_key_arn is not None:
                raise PlanPermissionRepairError(
                    "IAM_BINDING_MALFORMED",
                    "AWS-owned KMS mode cannot carry a key ARN",
                )
        elif (
            self.identity_center_kms_key_arn is None
            or _IDENTITY_CENTER_KMS_ARN.fullmatch(
                self.identity_center_kms_key_arn
            )
            is None
        ):
            raise PlanPermissionRepairError(
                "IAM_BINDING_MALFORMED",
                "customer-managed KMS mode requires the exact key ARN",
            )
        if any("${" in value for value in self._replacement_values()):
            raise PlanPermissionRepairError(
                "IAM_BINDING_MALFORMED",
                "effective-IAM binding contains a placeholder",
            )

    @classmethod
    def from_seed(cls, seed: Mapping[str, Any]) -> "PlanRepairIamBindings":
        """Materialize bindings from the already validated private seed."""

        try:
            return cls(
                repair_id=str(seed["repair_id"]),
                code_signing_config_arn=str(
                    seed["expected_code_signing_config_arn"]
                ),
                repair_ledger_kms_key_arn=str(seed["ledger_kms_key_arn"]),
                identity_center_instance_arn=str(seed["instance_arn"]),
                plan_permission_set_arn=str(seed["permission_set_arn"]),
                repair_invoker_permission_set_arn=str(
                    seed["repair_invoker_permission_set_arn"]
                ),
                identity_store_id=str(seed["identity_store_id"]),
                repair_principal_id=str(seed["principal_id"]),
                identity_center_kms_mode=str(seed["identity_center_kms_mode"]),
                identity_center_kms_key_arn=(
                    str(seed["identity_center_kms_key_arn"])
                    if seed.get("identity_center_kms_key_arn")
                    else None
                ),
            )
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, PlanPermissionRepairError):
                raise
            raise PlanPermissionRepairError(
                "IAM_BINDING_MALFORMED",
                "effective-IAM seed is incomplete",
            ) from exc

    @property
    def identity_store_arn(self) -> str:
        return (
            "arn:aws:identitystore::839393571433:identitystore/"
            f"{self.identity_store_id}"
        )

    @property
    def repair_principal_user_arn(self) -> str:
        return f"arn:aws:identitystore:::user/{self.repair_principal_id}"

    def _replacement_values(self) -> tuple[str, ...]:
        return tuple(
            value
            for value in (
                self.repair_id,
                self.code_signing_config_arn,
                self.repair_ledger_kms_key_arn,
                self.identity_center_instance_arn,
                self.plan_permission_set_arn,
                self.repair_invoker_permission_set_arn,
                self.identity_store_arn,
                self.repair_principal_user_arn,
                self.identity_center_kms_key_arn,
            )
            if value is not None
        )

    def normalization_replacements(self) -> tuple[tuple[str, str], ...]:
        replacements = (
            (self.repair_id, "${repair_id}"),
            (self.code_signing_config_arn, "${code_signing_config_arn}"),
            (
                self.repair_ledger_kms_key_arn,
                "${repair_ledger_kms_key_arn}",
            ),
            (
                self.identity_center_instance_arn,
                "${identity_center_instance_arn}",
            ),
            (self.plan_permission_set_arn, "${plan_permission_set_arn}"),
            (
                self.repair_invoker_permission_set_arn,
                "${repair_invoker_permission_set_arn}",
            ),
            (self.identity_store_arn, "${identity_store_arn}"),
            (
                self.repair_principal_user_arn,
                "${repair_principal_user_arn}",
            ),
        )
        if self.identity_center_kms_key_arn is not None:
            replacements += (
                (
                    self.identity_center_kms_key_arn,
                    "${identity_center_kms_key_arn}",
                ),
            )
        return tuple(sorted(replacements, key=lambda item: len(item[0]), reverse=True))


@dataclass(frozen=True, slots=True)
class ExpectedIamRole:
    logical_resource_id: str
    account_id: str
    role_name: str
    path: str
    arn: str
    max_session_duration: int
    trust_policy_digest: str
    inline_policy_name: str
    normalized_inline_policy_digests: Mapping[str, str]

    def policy_digest_for(self, kms_mode: str) -> str:
        try:
            return self.normalized_inline_policy_digests[kms_mode]
        except KeyError as exc:  # Defensive; manifest validation is authoritative.
            raise PlanPermissionRepairError(
                "IAM_CONTROL_MALFORMED",
                "effective-IAM control lacks the selected KMS mode",
            ) from exc


@dataclass(frozen=True, slots=True)
class IamRoleSnapshot:
    account_id: str
    role_name: str
    path: str
    arn: str
    max_session_duration: int
    trust_policy_digest: str
    inline_policy_name: str
    normalized_inline_policy_digest: str
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
            "normalized_inline_policy_digest": (
                self.normalized_inline_policy_digest
            ),
            "attached_managed_policy_arns": list(
                self.attached_managed_policy_arns
            ),
            "permissions_boundary_arn": self.permissions_boundary_arn,
        }


@dataclass(frozen=True, slots=True)
class IamEffectiveAuthoritySnapshot:
    authority_roles: tuple[IamRoleSnapshot, ...]
    management_roles: tuple[IamRoleSnapshot, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "authority_roles": [role.as_dict() for role in self.authority_roles],
            "management_roles": [
                role.as_dict() for role in self.management_roles
            ],
        }

    def digest(self) -> str:
        return digest_value(self.as_dict())


def _duplicate_rejecting_object(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PlanPermissionRepairError(
                "IAM_JSON_DUPLICATE_KEY",
                "effective-IAM JSON contains a duplicate key",
            )
        result[key] = value
    return result


def _strict_json_object(value: Any, *, code: str) -> Mapping[str, Any]:
    if isinstance(value, str) and value:
        try:
            parsed = json.loads(
                unquote(value), object_pairs_hook=_duplicate_rejecting_object
            )
        except PlanPermissionRepairError:
            raise
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise PlanPermissionRepairError(
                code, "effective-IAM document is malformed"
            ) from exc
    elif isinstance(value, Mapping):
        try:
            encoded = json.dumps(
                dict(value),
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
            )
            parsed = json.loads(
                encoded, object_pairs_hook=_duplicate_rejecting_object
            )
        except PlanPermissionRepairError:
            raise
        except (TypeError, ValueError) as exc:
            raise PlanPermissionRepairError(
                code, "effective-IAM document is not strict JSON"
            ) from exc
    else:
        raise PlanPermissionRepairError(
            code, "effective-IAM document must be a JSON object"
        )
    if not isinstance(parsed, dict):
        raise PlanPermissionRepairError(
            code, "effective-IAM document must be a JSON object"
        )
    return parsed


def _safe_control_path(repo_root: Path, relative_path: Path) -> Path:
    try:
        root = repo_root.resolve(strict=True)
        unresolved = root / relative_path
        if unresolved.is_symlink():
            raise PlanPermissionRepairError(
                "IAM_CONTROL_UNAVAILABLE",
                "effective-IAM control artifact is unsafe",
            )
        candidate = unresolved.resolve(strict=True)
        candidate.relative_to(root)
    except PlanPermissionRepairError:
        raise
    except (OSError, ValueError) as exc:
        raise PlanPermissionRepairError(
            "IAM_CONTROL_UNAVAILABLE",
            "effective-IAM control artifact is unavailable",
        ) from exc
    if not candidate.is_file():
        raise PlanPermissionRepairError(
            "IAM_CONTROL_UNAVAILABLE",
            "effective-IAM control artifact is unsafe",
        )
    return candidate


def load_expected_roles(
    *, repo_root: Path | None = None
) -> tuple[ExpectedIamRole, ...]:
    """Load and validate the closed six-role control inventory."""

    root = repo_root or Path(__file__).resolve().parents[1]
    path = _safe_control_path(root, CONTROL_PATH)
    try:
        document = _strict_json_object(
            path.read_text(encoding="utf-8"), code="IAM_CONTROL_MALFORMED"
        )
    except OSError as exc:
        raise PlanPermissionRepairError(
            "IAM_CONTROL_UNAVAILABLE",
            "effective-IAM control artifact is unreadable",
        ) from exc
    if set(document) != {
        "schema_version",
        "control_id",
        "authority_roles",
        "management_roles",
    } or document.get("schema_version") != "1.0" or document.get(
        "control_id"
    ) != CONTROL_ID:
        raise PlanPermissionRepairError(
            "IAM_CONTROL_MALFORMED",
            "effective-IAM control envelope differs",
        )
    authority = document.get("authority_roles")
    management = document.get("management_roles")
    if not isinstance(authority, list) or not isinstance(management, list):
        raise PlanPermissionRepairError(
            "IAM_CONTROL_MALFORMED",
            "effective-IAM control role inventory is malformed",
        )
    raw_roles = authority + management
    if len(authority) != 4 or len(management) != 2 or len(raw_roles) != 6:
        raise PlanPermissionRepairError(
            "IAM_CONTROL_MALFORMED",
            "effective-IAM control role inventory differs",
        )
    roles: list[ExpectedIamRole] = []
    required = {
        "logical_resource_id",
        "account_id",
        "role_name",
        "path",
        "arn",
        "max_session_duration",
        "trust_policy_digest",
        "inline_policy_name",
        "normalized_inline_policy_digests",
    }
    for index, (raw, identity) in enumerate(zip(raw_roles, _ROLE_IDENTITIES)):
        if not isinstance(raw, Mapping) or set(raw) != required:
            raise PlanPermissionRepairError(
                "IAM_CONTROL_MALFORMED",
                "effective-IAM role control is malformed",
            )
        logical_id, account_id, role_name, path_value, policy_name = identity
        expected_arn = f"arn:aws:iam::{account_id}:role{path_value}{role_name}"
        digests = raw.get("normalized_inline_policy_digests")
        if (
            raw.get("logical_resource_id") != logical_id
            or raw.get("account_id") != account_id
            or raw.get("role_name") != role_name
            or raw.get("path") != path_value
            or raw.get("arn") != expected_arn
            or raw.get("max_session_duration") != 3600
            or raw.get("inline_policy_name") != policy_name
            or not isinstance(raw.get("trust_policy_digest"), str)
            or _DIGEST.fullmatch(str(raw["trust_policy_digest"])) is None
            or not isinstance(digests, Mapping)
            or set(digests) != KMS_MODES
            or any(
                not isinstance(value, str)
                or _DIGEST.fullmatch(value) is None
                for value in digests.values()
            )
            or (index < 4 and account_id != AUTHORITY_ACCOUNT_ID)
            or (index >= 4 and account_id != MANAGEMENT_ACCOUNT_ID)
        ):
            raise PlanPermissionRepairError(
                "IAM_CONTROL_MALFORMED",
                "effective-IAM role control binding differs",
            )
        roles.append(
            ExpectedIamRole(
                logical_resource_id=logical_id,
                account_id=account_id,
                role_name=role_name,
                path=path_value,
                arn=expected_arn,
                max_session_duration=3600,
                trust_policy_digest=str(raw["trust_policy_digest"]),
                inline_policy_name=policy_name,
                normalized_inline_policy_digests=dict(digests),
            )
        )
    return tuple(roles)


def normalize_policy_bindings(
    policy: Mapping[str, Any], bindings: PlanRepairIamBindings
) -> Mapping[str, Any]:
    """Replace only validated live bindings with reviewed placeholder tokens."""

    replacements = bindings.normalization_replacements()

    def normalize(value: Any) -> Any:
        if isinstance(value, str):
            result = value
            for live_value, placeholder in replacements:
                result = result.replace(live_value, placeholder)
            return result
        if isinstance(value, list):
            return [normalize(item) for item in value]
        if isinstance(value, Mapping):
            return {str(key): normalize(item) for key, item in value.items()}
        if value is None or type(value) in {bool, int, float}:
            return value
        raise PlanPermissionRepairError(
            "IAM_INLINE_POLICY_MALFORMED",
            "effective-IAM policy contains a non-JSON value",
        )

    normalized = normalize(dict(policy))
    if not isinstance(normalized, Mapping):  # Defensive; policy is an object.
        raise PlanPermissionRepairError(
            "IAM_INLINE_POLICY_MALFORMED",
            "effective-IAM policy normalization failed",
        )
    return normalized


class AwsPlanRepairIamEffectiveAuthorityVerifier:
    """Read and fail closed on any effective-authority drift."""

    def __init__(
        self,
        *,
        authority_iam: Any,
        management_iam: Any,
        repo_root: Path | None = None,
    ) -> None:
        self._authority_iam = authority_iam
        self._management_iam = management_iam
        self._repo_root = repo_root or Path(__file__).resolve().parents[1]

    @staticmethod
    def _call(client: Any, method_name: str, **kwargs: Any) -> Mapping[str, Any]:
        try:
            response = getattr(client, method_name)(**kwargs)
        except PlanPermissionRepairError:
            raise
        except Exception as exc:
            raise PlanPermissionRepairError(
                "IAM_PROVIDER_FAILURE",
                "effective-IAM readback failed",
            ) from exc
        if not isinstance(response, Mapping):
            raise PlanPermissionRepairError(
                "IAM_PROVIDER_RESPONSE_MALFORMED",
                "effective-IAM response must be an object",
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
        for _ in range(MAX_IAM_PAGES):
            call_kwargs = dict(kwargs)
            if marker is not None:
                call_kwargs["Marker"] = marker
            response = self._call(client, method_name, **call_kwargs)
            page = response.get(result_key)
            if not isinstance(page, list):
                raise PlanPermissionRepairError(
                    "IAM_PROVIDER_RESPONSE_MALFORMED",
                    "effective-IAM inventory page is malformed",
                )
            values.extend(page)
            if len(values) > MAX_IAM_ITEMS:
                raise PlanPermissionRepairError(
                    "IAM_INVENTORY_LIMIT",
                    "effective-IAM inventory exceeded the item limit",
                )
            truncated = response.get("IsTruncated")
            next_marker = response.get("Marker")
            if type(truncated) is not bool:
                raise PlanPermissionRepairError(
                    "IAM_PROVIDER_RESPONSE_MALFORMED",
                    "effective-IAM pagination state is malformed",
                )
            if not truncated:
                if next_marker is not None:
                    raise PlanPermissionRepairError(
                        "IAM_PROVIDER_RESPONSE_MALFORMED",
                        "terminal effective-IAM page carries a marker",
                    )
                return values
            if not isinstance(next_marker, str) or not next_marker:
                raise PlanPermissionRepairError(
                    "IAM_PROVIDER_RESPONSE_MALFORMED",
                    "effective-IAM pagination marker is malformed",
                )
            if next_marker in seen_markers:
                raise PlanPermissionRepairError(
                    "IAM_PAGINATION_CYCLE",
                    "effective-IAM pagination repeated a marker",
                )
            seen_markers.add(next_marker)
            marker = next_marker
        raise PlanPermissionRepairError(
            "IAM_PAGINATION_LIMIT",
            "effective-IAM inventory exceeded the page limit",
        )

    def _read_role(
        self,
        client: Any,
        spec: ExpectedIamRole,
        bindings: PlanRepairIamBindings,
    ) -> IamRoleSnapshot:
        response = self._call(client, "get_role", RoleName=spec.role_name)
        role = response.get("Role")
        if not isinstance(role, Mapping):
            raise PlanPermissionRepairError(
                "IAM_ROLE_READBACK_MALFORMED",
                "effective-IAM role is malformed",
            )
        if (
            role.get("RoleName") != spec.role_name
            or role.get("Path") != spec.path
            or role.get("Arn") != spec.arn
        ):
            raise PlanPermissionRepairError(
                "IAM_ROLE_BINDING_MISMATCH",
                "effective-IAM role binding differs",
            )
        if role.get("MaxSessionDuration") != spec.max_session_duration:
            raise PlanPermissionRepairError(
                "IAM_ROLE_SESSION_MISMATCH",
                "effective-IAM role session duration differs",
            )
        if role.get("PermissionsBoundary") is not None:
            raise PlanPermissionRepairError(
                "IAM_ROLE_BOUNDARY_PRESENT",
                "effective-IAM role has a permissions boundary",
            )
        trust = _strict_json_object(
            role.get("AssumeRolePolicyDocument"), code="IAM_TRUST_MALFORMED"
        )
        if digest_value(trust) != spec.trust_policy_digest:
            raise PlanPermissionRepairError(
                "IAM_TRUST_MISMATCH",
                "effective-IAM trust differs from the reviewed control",
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
            raise PlanPermissionRepairError(
                "IAM_MANAGED_POLICY_INVENTORY_MALFORMED",
                "effective-IAM managed-policy inventory is malformed",
            )
        attached_arns = tuple(sorted(str(item["PolicyArn"]) for item in attached))
        if len(attached_arns) != len(set(attached_arns)):
            raise PlanPermissionRepairError(
                "IAM_MANAGED_POLICY_INVENTORY_DUPLICATE",
                "effective-IAM managed-policy inventory has duplicates",
            )
        if attached_arns:
            raise PlanPermissionRepairError(
                "IAM_MANAGED_POLICY_PRESENT",
                "effective-IAM role has a managed-policy attachment",
            )

        inline_raw = self._paginate(
            client,
            "list_role_policies",
            "PolicyNames",
            RoleName=spec.role_name,
        )
        if any(not isinstance(name, str) or not name for name in inline_raw):
            raise PlanPermissionRepairError(
                "IAM_INLINE_POLICY_INVENTORY_MALFORMED",
                "effective-IAM inline-policy inventory is malformed",
            )
        inline_names = tuple(sorted(inline_raw))
        if len(inline_names) != len(set(inline_names)):
            raise PlanPermissionRepairError(
                "IAM_INLINE_POLICY_INVENTORY_DUPLICATE",
                "effective-IAM inline-policy inventory has duplicates",
            )
        if inline_names != (spec.inline_policy_name,):
            raise PlanPermissionRepairError(
                "IAM_INLINE_POLICY_SET_MISMATCH",
                "effective-IAM inline-policy names differ",
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
            raise PlanPermissionRepairError(
                "IAM_INLINE_POLICY_BINDING_MISMATCH",
                "effective-IAM inline-policy binding differs",
            )
        policy = _strict_json_object(
            policy_response.get("PolicyDocument"),
            code="IAM_INLINE_POLICY_MALFORMED",
        )
        normalized_policy = normalize_policy_bindings(policy, bindings)
        normalized_digest = digest_value(normalized_policy)
        if normalized_digest != spec.policy_digest_for(
            bindings.identity_center_kms_mode
        ):
            raise PlanPermissionRepairError(
                "IAM_INLINE_POLICY_MISMATCH",
                "effective-IAM inline policy differs from the reviewed control",
            )
        return IamRoleSnapshot(
            account_id=spec.account_id,
            role_name=spec.role_name,
            path=spec.path,
            arn=spec.arn,
            max_session_duration=spec.max_session_duration,
            trust_policy_digest=spec.trust_policy_digest,
            inline_policy_name=spec.inline_policy_name,
            normalized_inline_policy_digest=normalized_digest,
            attached_managed_policy_arns=(),
            permissions_boundary_arn=None,
        )

    def snapshot(
        self, bindings: PlanRepairIamBindings
    ) -> IamEffectiveAuthoritySnapshot:
        specs = load_expected_roles(repo_root=self._repo_root)
        observed = IamEffectiveAuthoritySnapshot(
            authority_roles=tuple(
                self._read_role(self._authority_iam, spec, bindings)
                for spec in specs[:4]
            ),
            management_roles=tuple(
                self._read_role(self._management_iam, spec, bindings)
                for spec in specs[4:]
            ),
        )
        if len(observed.authority_roles) != 4 or len(
            observed.management_roles
        ) != 2:
            raise PlanPermissionRepairError(
                "IAM_SNAPSHOT_INCOMPLETE",
                "effective-IAM snapshot is incomplete",
            )
        return observed


class IamEffectiveAuthorityGuardedIdentityCenterPort:
    """Guard every snapshot and protected effect without changing the core port."""

    def __init__(
        self,
        *,
        delegate: Any,
        verifier: AwsPlanRepairIamEffectiveAuthorityVerifier,
        bindings: PlanRepairIamBindings,
    ) -> None:
        self._delegate = delegate
        self._verifier = verifier
        self._bindings = bindings

    def _guard(self) -> IamEffectiveAuthoritySnapshot:
        return self._verifier.snapshot(self._bindings)

    def discover(self, seed: Mapping[str, Any]) -> Any:
        self._guard()
        return self._delegate.discover(seed)

    def snapshot(self, intent: Mapping[str, Any]) -> Any:
        self._guard()
        return self._delegate.snapshot(intent)

    def put_inline_policy(
        self, intent: Mapping[str, Any], policy_json: str
    ) -> None:
        self._guard()
        self._delegate.put_inline_policy(intent, policy_json)

    def provision_permission_set(self, intent: Mapping[str, Any]) -> Any:
        self._guard()
        return self._delegate.provision_permission_set(intent)

    def describe_provisioning(
        self, intent: Mapping[str, Any], request_id: str
    ) -> str:
        # Polling is read-only. The immediately preceding effect and the final
        # state snapshot are both guarded, avoiding six-role scans per poll.
        return self._delegate.describe_provisioning(intent, request_id)


__all__ = [
    "AUTHORITY_ACCOUNT_ID",
    "AwsPlanRepairIamEffectiveAuthorityVerifier",
    "CONTROL_PATH",
    "IamEffectiveAuthorityGuardedIdentityCenterPort",
    "IamEffectiveAuthoritySnapshot",
    "IamRoleSnapshot",
    "MANAGEMENT_ACCOUNT_ID",
    "PlanRepairIamBindings",
    "load_expected_roles",
    "normalize_policy_bindings",
]
