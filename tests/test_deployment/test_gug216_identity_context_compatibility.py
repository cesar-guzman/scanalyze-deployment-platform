"""GUG-216 managed identity-context compatibility guard tests."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

import tooling.platform_authority_identity_context_compatibility as compatibility_module
from tooling.platform_authority_identity_context_compatibility import (
    AWS_IDENTITY_CONTEXT_POLICY_ARN,
    BLOCKED_ACTION_UNSUPPORTED,
    BROKER_REQUIRED_ACTION,
    COMPATIBLE_REVIEWED_ACTION,
    POLICY_SNAPSHOT_DIGEST,
    CompatibilityError,
    bundled_compatibility_decision,
    canonical_digest,
    evaluate_identity_context_policy,
    load_bundled_policy_snapshot,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT = (
    REPO_ROOT
    / "policies/iam/aws-managed-identity-context-allowlist-v12.snapshot.json"
)


def _current_document() -> dict[str, object]:
    return copy.deepcopy(load_bundled_policy_snapshot())


def _evaluate(
    document: dict[str, object],
    *,
    policy_arn: str = AWS_IDENTITY_CONTEXT_POLICY_ARN,
    version: str = "v12",
    reviewed_digest: str | None = None,
):
    return evaluate_identity_context_policy(
        document,
        policy_arn=policy_arn,
        default_version_id=version,
        required_action=BROKER_REQUIRED_ACTION,
        reviewed_digest=reviewed_digest or canonical_digest(document),
    )


def test_bundled_v12_snapshot_blocks_lambda_before_any_exchange() -> None:
    decision = bundled_compatibility_decision()
    assert decision.status == BLOCKED_ACTION_UNSUPPORTED
    assert decision.required_action == "lambda:InvokeFunction"
    assert decision.policy_version == "v12"
    assert decision.policy_digest == POLICY_SNAPSHOT_DIGEST
    assert decision.token_issued is False
    assert decision.sts_session_issued is False
    assert decision.broker_invocation_performed is False
    assert SNAPSHOT.exists()


def test_bundled_snapshot_digest_is_independently_pinned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tampered = _current_document()
    tampered["Statement"][0]["NotAction"].append(BROKER_REQUIRED_ACTION)
    path = tmp_path / "tampered-policy.json"
    path.write_text(json.dumps(tampered), encoding="utf-8")
    monkeypatch.setattr(compatibility_module, "POLICY_SNAPSHOT_PATH", path)
    with pytest.raises(CompatibilityError, match="POLICY_DIGEST_UNREVIEWED"):
        bundled_compatibility_decision()


def test_bundled_snapshot_models_explicit_deny_not_action() -> None:
    document = _current_document()
    assert document["Version"] == "2012-10-17"
    assert len(document["Statement"]) == 1
    statement = document["Statement"][0]
    assert statement["Effect"] == "Deny"
    assert statement["Resource"] == "*"
    assert "lambda:InvokeFunction" not in statement["NotAction"]
    assert "sts:SetContext" in statement["NotAction"]


def test_target_role_allow_cannot_override_managed_explicit_deny() -> None:
    target_role_allow = {
        "Effect": "Allow",
        "Action": "lambda:InvokeFunction",
        "Resource": "arn:aws:lambda:us-east-1:111122223333:function:synthetic:classify",
    }
    assert target_role_allow["Effect"] == "Allow"
    assert _evaluate(_current_document()).status == BLOCKED_ACTION_UNSUPPORTED


def test_future_action_support_requires_new_reviewed_digest() -> None:
    current = _current_document()
    old_digest = canonical_digest(current)
    future = copy.deepcopy(current)
    future["Statement"][0]["NotAction"].append(BROKER_REQUIRED_ACTION)
    with pytest.raises(CompatibilityError, match="POLICY_DIGEST_UNREVIEWED"):
        _evaluate(future, reviewed_digest=old_digest)
    decision = _evaluate(future, reviewed_digest=canonical_digest(future))
    assert decision.status == COMPATIBLE_REVIEWED_ACTION


@pytest.mark.parametrize(
    ("mutation", "code"),
    (
        (lambda d: d.update({"Version": "2008-10-17"}), "POLICY_DOCUMENT_MALFORMED"),
        (lambda d: d.update({"Statement": []}), "POLICY_DOCUMENT_MALFORMED"),
        (
            lambda d: d["Statement"][0].update({"Effect": "Allow"}),
            "POLICY_DOCUMENT_MALFORMED",
        ),
        (
            lambda d: d["Statement"][0].update({"Action": ["sts:SetContext"]}),
            "POLICY_DOCUMENT_MALFORMED",
        ),
        (
            lambda d: d["Statement"][0].update({"Resource": "arn:aws:iam::aws:role/x"}),
            "POLICY_DOCUMENT_MALFORMED",
        ),
        (
            lambda d: d["Statement"][0]["NotAction"].append("sts:SetContext"),
            "POLICY_DOCUMENT_MALFORMED",
        ),
        (
            lambda d: d["Statement"].append(copy.deepcopy(d["Statement"][0])),
            "POLICY_DOCUMENT_MALFORMED",
        ),
    ),
)
def test_malformed_or_ambiguous_managed_policy_fails_closed(
    mutation,
    code: str,
) -> None:
    document = _current_document()
    mutation(document)
    with pytest.raises(CompatibilityError, match=code):
        _evaluate(document)


def test_wrong_policy_arn_and_version_fail_closed() -> None:
    document = _current_document()
    with pytest.raises(CompatibilityError, match="POLICY_ARN_UNEXPECTED"):
        _evaluate(document, policy_arn="arn:aws:iam::111122223333:policy/foreign")
    with pytest.raises(CompatibilityError, match="POLICY_VERSION_UNEXPECTED"):
        _evaluate(document, version="not-a-version")


def test_compatibility_receipt_is_sanitized_and_deterministic() -> None:
    receipt = bundled_compatibility_decision().to_receipt(
        observed_at="2030-01-01T00:00:00Z"
    )
    encoded = json.dumps(receipt, sort_keys=True)
    assert receipt["status"] == BLOCKED_ACTION_UNSUPPORTED
    assert receipt["current_human_operator_count"] == 1
    assert receipt["independent_approver_available"] is False
    assert receipt["production"] is False
    for forbidden in (
        "accessToken",
        "refreshToken",
        "identityContext",
        "ContextAssertion",
        "AccessKeyId",
        "SecretAccessKey",
        "SessionToken",
        "UserId",
        "email",
    ):
        assert forbidden not in encoded
