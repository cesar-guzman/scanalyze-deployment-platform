"""GUG-94 closed HTTP route and PEP contract tests."""
from __future__ import annotations

from fastapi.routing import APIRoute

from app.api.v1.router import router
from app.authorization import ROUTE_OPERATION_POLICY_ATTRIBUTE
from app.enterprise_authorization import OperationId, operation_policy


EXPECTED_LIFECYCLE_ROUTES = {
    ("GET", "/api/v1/admin/roles"): OperationId.AUTHORIZATION_ROLES_READ,
    ("GET", "/api/v1/admin/memberships"): OperationId.AUTHORIZATION_MEMBERSHIPS_LIST,
    ("POST", "/api/v1/admin/invitations"): OperationId.AUTHORIZATION_INVITATIONS_CREATE,
    (
        "POST",
        "/api/v1/admin/memberships/{membership_reference}/activations",
    ): OperationId.AUTHORIZATION_MEMBERSHIPS_ACTIVATE,
    (
        "POST",
        "/api/v1/admin/memberships/{membership_reference}/role-changes",
    ): OperationId.AUTHORIZATION_MEMBERSHIPS_ROLE_CHANGE,
    (
        "POST",
        "/api/v1/admin/memberships/{membership_reference}/suspensions",
    ): OperationId.AUTHORIZATION_MEMBERSHIPS_SUSPEND,
    (
        "POST",
        "/api/v1/admin/memberships/{membership_reference}/reactivations",
    ): OperationId.AUTHORIZATION_MEMBERSHIPS_REACTIVATE,
    (
        "POST",
        "/api/v1/admin/memberships/{membership_reference}/revocations",
    ): OperationId.AUTHORIZATION_MEMBERSHIPS_REVOKE,
    (
        "POST",
        "/api/v1/admin/memberships/{membership_reference}/session-revocations",
    ): OperationId.AUTHORIZATION_SESSIONS_REVOKE,
    ("GET", "/api/v1/admin/audit-events"): OperationId.AUTHORIZATION_AUDIT_READ,
}


def test_every_lifecycle_route_has_one_closed_operation_pep() -> None:
    actual = {}
    for route in router.routes:
        if not isinstance(route, APIRoute) or not route.path.startswith("/api/v1/admin"):
            continue
        marked = [
            dependency.call
            for dependency in route.dependant.dependencies
            if hasattr(dependency.call, ROUTE_OPERATION_POLICY_ATTRIBUTE)
        ]
        assert len(marked) == 1
        operation = getattr(marked[0], ROUTE_OPERATION_POLICY_ATTRIBUTE)
        for method in route.methods:
            actual[(method, route.path)] = operation
    assert actual == EXPECTED_LIFECYCLE_ROUTES


def test_lifecycle_mutations_are_human_only_step_up_operations() -> None:
    mutations = set(EXPECTED_LIFECYCLE_ROUTES.values()) - {
        OperationId.AUTHORIZATION_ROLES_READ,
        OperationId.AUTHORIZATION_MEMBERSHIPS_LIST,
        OperationId.AUTHORIZATION_AUDIT_READ,
    }
    for operation in mutations:
        policy = operation_policy(operation)
        assert policy.step_up_required
        assert not policy.m2m_allowed


def test_lifecycle_reads_never_grant_m2m_administration() -> None:
    for operation in (
        OperationId.AUTHORIZATION_ROLES_READ,
        OperationId.AUTHORIZATION_MEMBERSHIPS_LIST,
        OperationId.AUTHORIZATION_AUDIT_READ,
    ):
        policy = operation_policy(operation)
        assert not policy.m2m_allowed
