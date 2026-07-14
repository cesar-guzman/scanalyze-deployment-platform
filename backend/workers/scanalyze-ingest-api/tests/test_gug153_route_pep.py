"""GUG-153 closed route-to-operation PEP contract tests.

Route operation markers drive the human PDP, while the existing action markers
remain the reviewed M2M compatibility contract from GUG-102. The two policies
are related, but are not interchangeable, and this inventory fails closed when
either mapping drifts.
"""
from __future__ import annotations

from typing import Any

import pytest
from fastapi.routing import APIRoute

from app.api.v1.router import router as v1_router
from app.authorization import (
    ROUTE_ACTION_POLICY_ATTRIBUTE,
    ROUTE_OPERATION_POLICY_ATTRIBUTE,
)
from app.enterprise_authorization import OperationId
from app.main import app


EXPECTED_ROUTE_OPERATIONS = {
    ("POST", "/api/v1/documents"): "documents.create",
    ("POST", "/api/v1/documents/{document_id}/submit"): "documents.submit",
    ("GET", "/api/v1/documents/{document_id}"): "documents.read_metadata",
    ("GET", "/api/v1/documents/{document_id}/result"): "results.read_full",
    (
        "GET",
        "/api/v1/documents/{document_id}/artifacts",
    ): "artifacts.list_metadata",
    (
        "GET",
        "/api/v1/documents/{document_id}/download",
    ): "artifacts.download",
    (
        "GET",
        "/api/v1/documents/{document_id}/artifacts/{artifact_id}/download",
    ): "artifacts.download",
    ("POST", "/api/v1/batches"): "batches.create",
    ("GET", "/api/v1/batches/{batch_id}"): "batches.read_metadata",
    (
        "GET",
        "/api/v1/batches/{batch_id}/documents",
    ): "batches.read_metadata",
    ("GET", "/api/v1/batches/{batch_id}/manifest"): "exports.execute",
    ("GET", "/api/v1/batches/{batch_id}/exports/json"): "exports.execute",
    ("GET", "/api/v1/batches/{batch_id}/exports/csv"): "exports.execute",
    ("GET", "/api/v1/batches/{batch_id}/exports/zip"): "exports.execute",
    ("GET", "/api/v1/analytics/dashboard"): "metrics.read_identified",
    ("GET", "/api/v1/analytics/overview"): "metrics.read",
    ("GET", "/api/v1/analytics/pages-by-user"): "metrics.read_identified",
    ("GET", "/api/v1/analytics/by-day"): "metrics.read",
    ("GET", "/api/v1/analytics/by-batch"): "metrics.read",
    ("GET", "/api/v1/analytics/by-doc-type"): "metrics.read",
    ("GET", "/api/v1/analytics/costs"): "metrics.read",
    ("GET", "/api/v1/analytics/export-ine"): "exports.execute",
    (
        "GET",
        "/api/v1/addons/employee-profiles/status",
    ): "deployment_configuration.read",
    (
        "GET",
        "/api/v1/addons/employee-profiles/export/csv",
    ): "exports.execute",
    (
        "POST",
        "/api/v1/addons/employee-profiles/generate",
    ): "employee_profiles.generate",
    (
        "GET",
        "/api/v1/addons/employee-profiles/jobs/{job_id}",
    ): "employee_profiles.read_job",
    (
        "GET",
        "/api/v1/addons/employee-profiles",
    ): "employee_profiles.list_masked",
    (
        "GET",
        "/api/v1/addons/employee-profiles/{profile_id}/export/json",
    ): "exports.execute",
    (
        "GET",
        "/api/v1/addons/employee-profiles/{profile_id}/export/csv",
    ): "exports.execute",
    (
        "GET",
        "/api/v1/addons/employee-profiles/{profile_id}",
    ): "employee_profiles.read_full",
    ("GET", "/api/v1/admin/roles"): "authorization_administration.roles.read",
    ("GET", "/api/v1/admin/memberships"): "authorization_administration.memberships.list",
    ("POST", "/api/v1/admin/invitations"): "authorization_administration.invitations.create",
    (
        "POST",
        "/api/v1/admin/memberships/{membership_reference}/activations",
    ): "authorization_administration.memberships.activate",
    (
        "POST",
        "/api/v1/admin/memberships/{membership_reference}/role-changes",
    ): "authorization_administration.memberships.change_role",
    (
        "POST",
        "/api/v1/admin/memberships/{membership_reference}/suspensions",
    ): "authorization_administration.memberships.suspend",
    (
        "POST",
        "/api/v1/admin/memberships/{membership_reference}/reactivations",
    ): "authorization_administration.memberships.reactivate",
    (
        "POST",
        "/api/v1/admin/memberships/{membership_reference}/revocations",
    ): "authorization_administration.memberships.revoke",
    (
        "POST",
        "/api/v1/admin/memberships/{membership_reference}/session-revocations",
    ): "authorization_administration.sessions.revoke",
    ("GET", "/api/v1/admin/audit-events"): "authorization_administration.audit.read",
}


# Keep these action sets byte-for-byte equivalent to the reviewed GUG-102 route
# contract.  Human sensitivity is expressed by OperationId and the human PDP;
# it must not silently broaden or narrow an existing M2M grant.
EXPECTED_M2M_ACTIONS_BY_OPERATION = {
    "documents.create": frozenset({"write"}),
    "documents.submit": frozenset({"write"}),
    "documents.read_metadata": frozenset({"read"}),
    "results.read_full": frozenset({"read", "admin"}),
    "artifacts.list_metadata": frozenset({"read"}),
    "artifacts.download": frozenset({"read", "admin"}),
    "batches.create": frozenset({"write"}),
    "batches.read_metadata": frozenset({"read"}),
    "exports.execute": frozenset({"read", "admin"}),
    "metrics.read_identified": frozenset({"read"}),
    "metrics.read": frozenset({"read"}),
    "deployment_configuration.read": frozenset({"read"}),
    "employee_profiles.generate": frozenset({"write"}),
    "employee_profiles.read_job": frozenset({"read"}),
    "employee_profiles.list_masked": frozenset({"read", "admin"}),
    "employee_profiles.read_full": frozenset({"read", "admin"}),
    "authorization_administration.roles.read": frozenset(),
    "authorization_administration.memberships.list": frozenset(),
    "authorization_administration.invitations.create": frozenset(),
    "authorization_administration.memberships.activate": frozenset(),
    "authorization_administration.memberships.change_role": frozenset(),
    "authorization_administration.memberships.suspend": frozenset(),
    "authorization_administration.memberships.reactivate": frozenset(),
    "authorization_administration.memberships.revoke": frozenset(),
    "authorization_administration.sessions.revoke": frozenset(),
    "authorization_administration.audit.read": frozenset(),
}


def _dependencies_with_attribute(route: APIRoute, attribute: str) -> list[Any]:
    return [
        dependency.call
        for dependency in route.dependant.dependencies
        if hasattr(dependency.call, attribute)
    ]


def _operation_value(operation: object) -> str:
    assert isinstance(operation, OperationId), (
        "route operation policies must use the closed, typed OperationId domain"
    )
    return operation.value


def test_operation_id_rejects_unmapped_operations_fail_closed() -> None:
    """Unknown, missing, and free-form operation identifiers are never valid."""

    for invalid in ("", "unmapped.operation", "documents.*", "metrics.read "):
        with pytest.raises(ValueError):
            OperationId(invalid)

    with pytest.raises((TypeError, ValueError)):
        OperationId(None)  # type: ignore[arg-type]


def test_all_40_protected_api_v1_routes_have_one_closed_operation_pep() -> None:
    """A new or unmarked protected route must break the closed inventory."""

    assert len(EXPECTED_ROUTE_OPERATIONS) == 40
    actual: dict[tuple[str, str], str] = {}

    for route in v1_router.routes:
        if not isinstance(route, APIRoute):
            continue

        operation_dependencies = _dependencies_with_attribute(
            route,
            ROUTE_OPERATION_POLICY_ATTRIBUTE,
        )
        assert len(operation_dependencies) == 1, (
            f"{route.path} must have exactly one enterprise operation PEP; "
            f"found {len(operation_dependencies)}"
        )
        operation = getattr(
            operation_dependencies[0],
            ROUTE_OPERATION_POLICY_ATTRIBUTE,
        )
        operation_value = _operation_value(operation)

        for method in route.methods:
            key = (method, route.path)
            assert key not in actual, f"duplicate protected route mapping: {key}"
            actual[key] = operation_value

    assert actual == EXPECTED_ROUTE_OPERATIONS


def test_only_public_health_routes_are_outside_the_operation_pep() -> None:
    """A newly mounted API route cannot bypass the closed business inventory."""

    protected: set[tuple[str, str]] = set()
    public: set[tuple[str, str]] = set()
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        operation_dependencies = _dependencies_with_attribute(
            route,
            ROUTE_OPERATION_POLICY_ATTRIBUTE,
        )
        target = protected if operation_dependencies else public
        target.update((method, route.path) for method in route.methods)

    assert protected == set(EXPECTED_ROUTE_OPERATIONS)
    assert public == {
        ("GET", "/health"),
        ("GET", "/api/v1/health"),
    }


def test_each_operation_pep_preserves_the_gug102_m2m_action_set() -> None:
    """The human PEP must not replace or weaken the existing M2M action gate."""

    assert set(EXPECTED_ROUTE_OPERATIONS.values()) == set(
        EXPECTED_M2M_ACTIONS_BY_OPERATION
    )

    for route in v1_router.routes:
        if not isinstance(route, APIRoute):
            continue

        operation_dependencies = _dependencies_with_attribute(
            route,
            ROUTE_OPERATION_POLICY_ATTRIBUTE,
        )
        assert len(operation_dependencies) == 1
        operation = getattr(
            operation_dependencies[0],
            ROUTE_OPERATION_POLICY_ATTRIBUTE,
        )
        operation_value = _operation_value(operation)

        action_dependencies = _dependencies_with_attribute(
            route,
            ROUTE_ACTION_POLICY_ATTRIBUTE,
        )
        assert len(action_dependencies) == 1, (
            f"{route.path} must preserve exactly one GUG-102 M2M action policy; "
            f"found {len(action_dependencies)}"
        )
        required_actions = getattr(
            action_dependencies[0],
            ROUTE_ACTION_POLICY_ATTRIBUTE,
        )
        assert required_actions == EXPECTED_M2M_ACTIONS_BY_OPERATION[operation_value]
