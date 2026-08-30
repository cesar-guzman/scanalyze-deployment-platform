"""Documentation contracts for the protected non-production live path."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
DEPLOYMENT_GUIDE = REPO_ROOT / "docs/deployment/nonproduction-live-engine.md"
OPERATIONS_GUIDE = (
    REPO_ROOT / "docs/operations/nonproduction-live-engine-reconciliation.md"
)
PHASE_GATES = REPO_ROOT / "docs/production-readiness/phase-gates.md"
ADR = REPO_ROOT / "ADR/ADR-033-nonproduction-live-engine-and-saved-plans.md"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _normalized(path: Path) -> str:
    return " ".join(_text(path).split())


def test_live_path_docs_bind_the_exact_private_interface() -> None:
    combined = "\n".join(_text(path) for path in (ADR, DEPLOYMENT_GUIDE, OPERATIONS_GUIDE))

    for required in (
        "live_input_claim_digest",
        "SCANALYZE_LIVE_INPUT_BUNDLE_B64",
        "SCANALYZE_GITHUB_ENVIRONMENT_COLLECTOR_PRIVATE_KEY",
        "GITHUB_ENVIRONMENT_COLLECTOR_APP_ID",
        "$RUNNER_TEMP/scanalyze-live-inputs",
        "nonprod-live-input-materializer.py",
        "nonprod-live-controller.py",
        "`run-terminal-apply` command remains unavailable",
        "public `apply` command is wired for DEV or staging",
        "nonprod-live-approval.py",
        "nonprod-live-github-approval-evidence.v1.schema.json",
        "deployment/live-input-claims/<deployment_id>/<layer>/<operation>.json",
        "LIVE_INPUTS_MATERIALIZED",
        "durable_readback_required",
        "terminal_operation_authorized",
        "scanalyze-<account-id>-tf-plan",
        "scanalyze-<account-id>-tf-evidence",
        "evidence_kms_key",
        "stable sealed authority projection",
        "Terraform state is deliberately absent from the pre-OIDC transport",
        "The full receipts are expected to differ by observation time",
    ):
        assert required in combined

    assert "live_input_request_digest" not in combined
    assert "$RUNNER_TEMP/scanalyze-live`" not in combined
    assert "scanalyze-<account-id>-tf-state" not in combined
    assert "stale_apply_recovery" not in combined


def test_live_path_docs_preserve_cost_blast_radius_and_recovery_boundaries() -> None:
    deployment = _normalized(DEPLOYMENT_GUIDE)
    operations = _normalized(OPERATIONS_GUIDE)

    for required in (
        "Cost and blast-radius controls",
        "one exact `dev` or `staging`",
        "maximum_cost_usd_micros",
        "cost_model_digest",
        "3,600-second platform-authority control-plane OIDC session",
        "one-hour destination terminal role session",
        "caps the protected job at 45",
        "one apply attempt",
    ):
        assert required in deployment

    for required in (
        "Cost and blast-radius gate",
        "budget breach",
        "`UNCERTAIN`",
        "do not retry",
        "Terraform state restore",
    ):
        assert required in operations


def test_live_path_docs_do_not_collapse_repository_dev_staging_and_production() -> None:
    deployment = _normalized(DEPLOYMENT_GUIDE)
    operations = _normalized(OPERATIONS_GUIDE)
    phase_gates = _text(PHASE_GATES)

    for required in (
        "Repository ready",
        "Connected DEV plan",
        "Connected DEV apply",
        "GUG-127 staging certified",
        "GUG-128 production pilot GO",
        "Production is **NO-GO**",
    ):
        assert required in deployment

    assert "This wiring is repository evidence only" in deployment
    assert "returns a successful exit code only for `HEALTHY`" in deployment
    assert "The public Apply path is wired in the repository" in operations
    assert "no connected protected non-production execution has yet proved it" in operations
    assert "`UNCERTAIN` permits only read-only reconciliation" in _normalized(ADR)

    assert "Nothing in this runbook authorizes that pilot" in operations
    ordered = (
        "repository review/CI",
        "protected connected DEV plan",
        "GUG-127 staging certification",
        "separate GUG-128 limited-production-pilot authorization",
    )
    positions = [phase_gates.index(value) for value in ordered]
    assert positions == sorted(positions)
