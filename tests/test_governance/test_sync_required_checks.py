from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import stat
import sys
from unittest.mock import patch

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "governance" / "sync-required-checks.py"
SPEC = importlib.util.spec_from_file_location("sync_required_checks", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
sync = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = sync
SPEC.loader.exec_module(sync)


REPOSITORY = "example/scanalyze-client"
BRANCH = "main"
EVIDENCE_SHA = "a" * 40
APP_ID = 15368
APP_SLUG = "github-actions"
PR_NUMBER = 3
WORKFLOW_PATH = ".github/workflows/policy.yml"
WORKFLOW_RUN_ID = 7001
STABLE_CONTEXTS = {"Lint policy", "Validate tooling"}
ADDED_CONTEXTS = {"Microservices validation gate"}
RETIRED_CONTEXTS = {"Validate bank-worker", "Validate ingest-api"}
TARGET_CONTEXTS = STABLE_CONTEXTS | ADDED_CONTEXTS
LEGACY_CONTEXTS = STABLE_CONTEXTS | RETIRED_CONTEXTS


def make_manifest() -> sync.PolicyManifest:
    checks = tuple(
        sync.ManifestCheck(
            context=context,
            workflow=WORKFLOW_PATH,
            job=context.lower().replace(" ", "_"),
        )
        for context in sorted(TARGET_CONTEXTS)
    )
    return sync.PolicyManifest(
        schema_version="1",
        default_branch=BRANCH,
        strict=True,
        expected_app_slug=APP_SLUG,
        checks=checks,
        added_contexts=frozenset(ADDED_CONTEXTS),
        retired_contexts=frozenset(RETIRED_CONTEXTS),
    )


def manifest_document(
    manifest: sync.PolicyManifest | None = None,
) -> dict[str, object]:
    selected = manifest or make_manifest()
    return {
        "schema_version": selected.schema_version,
        "scope": "repository",
        "default_branch": selected.default_branch,
        "required_status_checks": {
            "strict": selected.strict,
            "expected_app_slug": selected.expected_app_slug,
            "checks": [
                {
                    "context": check.context,
                    "workflow": check.workflow,
                    "job": check.job,
                }
                for check in selected.checks
            ],
        },
        "migration": {
            "added_contexts": sorted(selected.added_contexts),
            "retired_contexts": sorted(selected.retired_contexts),
        },
    }


def make_policy(
    contexts: set[str], *, strict: bool = True, app_id: int | None = APP_ID
) -> sync.RequiredStatusPolicy:
    return sync.RequiredStatusPolicy(
        strict=strict,
        checks=tuple(
            sorted(sync.CheckBinding(context=context, app_id=app_id) for context in contexts)
        ),
    )


def api_policy(policy: sync.RequiredStatusPolicy) -> dict[str, object]:
    return {
        "strict": policy.strict,
        "contexts": sorted(policy.contexts),
        "checks": [check.to_dict() for check in policy.checks],
    }


def pull_request(
    *,
    number: int = PR_NUMBER,
    state: str = "open",
    head_sha: str = EVIDENCE_SHA,
    base_ref: str = BRANCH,
) -> dict[str, object]:
    return {
        "id": 3001 + number,
        "number": number,
        "state": state,
        "head": {"sha": head_sha},
        "base": {"ref": base_ref, "repo": {"full_name": REPOSITORY}},
    }


def pull_request_association(
    *,
    number: int = PR_NUMBER,
    head_sha: str = EVIDENCE_SHA,
    base_ref: str = BRANCH,
) -> dict[str, object]:
    return {
        "number": number,
        "head": {"sha": head_sha},
        "base": {"ref": base_ref},
    }


def success_workflow_run(
    *,
    run_id: int = WORKFLOW_RUN_ID,
    path: str = WORKFLOW_PATH,
) -> dict[str, object]:
    return {
        "id": run_id,
        "event": "pull_request",
        "head_sha": EVIDENCE_SHA,
        "path": f"{path}@refs/pull/{PR_NUMBER}/merge",
        "status": "completed",
        "conclusion": "success",
        "repository": {"full_name": REPOSITORY},
        "pull_requests": [pull_request_association()],
    }


def success_evidence(contexts: set[str]) -> dict[str, object]:
    return {
        "total_count": len(contexts),
        "check_runs": [
            {
                "id": index,
                "name": context,
                "status": "completed",
                "conclusion": "success",
                "head_sha": EVIDENCE_SHA,
                "details_url": (
                    f"https://github.com/{REPOSITORY}/actions/runs/"
                    f"{WORKFLOW_RUN_ID}/job/{8000 + index}"
                ),
                "started_at": "2026-07-10T12:00:00Z",
                "completed_at": "2026-07-10T12:01:00Z",
                "app": {"id": APP_ID, "slug": APP_SLUG},
                "pull_requests": [pull_request_association()],
            }
            for index, context in enumerate(sorted(contexts), start=1)
        ],
    }


def success_jobs(contexts: set[str]) -> dict[int, dict[str, object]]:
    return {
        8000 + index: {
            "id": 8000 + index,
            "run_id": WORKFLOW_RUN_ID,
            "head_sha": EVIDENCE_SHA,
            "name": context,
            "status": "completed",
            "conclusion": "success",
            "html_url": (
                f"https://github.com/{REPOSITORY}/actions/runs/"
                f"{WORKFLOW_RUN_ID}/job/{8000 + index}"
            ),
            "check_run_url": (
                f"https://api.github.com/repos/{REPOSITORY}/check-runs/{index}"
            ),
        }
        for index, context in enumerate(sorted(contexts), start=1)
    }


def workflow_source(manifest: sync.PolicyManifest | None = None) -> str:
    selected = manifest or make_manifest()
    lines = ["name: Policy workflow", "on:", "  pull_request:", "jobs:"]
    for check in selected.checks:
        lines.extend(
            [
                f"  {check.job}:",
                f"    name: {check.context}",
                "    runs-on: ubuntu-latest",
            ]
        )
    return "\n".join(lines) + "\n"


@pytest.fixture(autouse=True)
def offline_workflow_source(monkeypatch: pytest.MonkeyPatch) -> None:
    manifest_bytes = json.dumps(manifest_document(), sort_keys=True).encode("utf-8")
    monkeypatch.setattr(
        sync,
        "read_git_blob",
        lambda revision, path: workflow_source(),
        raising=False,
    )
    monkeypatch.setattr(
        sync,
        "read_manifest_blob",
        lambda revision, path: manifest_bytes,
        raising=False,
    )
    monkeypatch.setattr(
        sync,
        "read_working_manifest",
        lambda path: manifest_bytes,
        raising=False,
    )


class FakeGitHub:
    def __init__(
        self,
        policy: sync.RequiredStatusPolicy,
        *,
        rules: list[dict[str, object]] | None = None,
        evidence: dict[str, object] | None = None,
        pull_requests: list[dict[str, object]] | None = None,
        workflow_runs: dict[int, dict[str, object]] | None = None,
        jobs: dict[int, dict[str, object]] | None = None,
        policy_reads: list[sync.RequiredStatusPolicy | Exception] | None = None,
        pull_request_reads: list[list[dict[str, object]]] | None = None,
        patch_failures: list[tuple[bool, Exception]] | None = None,
        rules_reads: list[list[dict[str, object]]] | None = None,
    ) -> None:
        self.policy = policy
        self.rules = rules or []
        self.evidence = evidence or success_evidence(TARGET_CONTEXTS)
        self.pull_requests = (
            [pull_request()] if pull_requests is None else pull_requests
        )
        self.workflow_runs = (
            {WORKFLOW_RUN_ID: success_workflow_run()}
            if workflow_runs is None
            else workflow_runs
        )
        self.jobs = success_jobs(TARGET_CONTEXTS) if jobs is None else jobs
        self.policy_reads = list(policy_reads or [])
        self.pull_request_reads = list(pull_request_reads or [])
        self.patch_failures = list(patch_failures or [])
        self.rules_reads = list(rules_reads or [])
        self.calls: list[tuple[list[str], str | None]] = []

    def __call__(self, args: list[str], *, input_data: str | None = None) -> object:
        arguments = list(args)
        self.calls.append((arguments, input_data))
        method = arguments[arguments.index("--method") + 1]
        endpoint = next(item for item in arguments if item.startswith("repos/"))

        if endpoint.endswith("/protection/required_status_checks"):
            if method == "GET":
                policy = self.policy_reads.pop(0) if self.policy_reads else self.policy
                if isinstance(policy, Exception):
                    raise policy
                return copy.deepcopy(api_policy(policy))
            if method == "PATCH":
                assert input_data is not None
                payload = json.loads(input_data)
                assert set(payload) == {"strict", "contexts", "checks"}
                assert payload["contexts"] == []
                desired = sync.required_policy_from_api(
                    {
                        "strict": payload["strict"],
                        "contexts": [check["context"] for check in payload["checks"]],
                        "checks": payload["checks"],
                    }
                )
                if self.patch_failures:
                    apply_before_failure, failure = self.patch_failures.pop(0)
                    if apply_before_failure:
                        self.policy = desired
                    raise failure
                self.policy = desired
                return api_policy(self.policy)

        if "/rules/branches/" in endpoint and method == "GET":
            rules = self.rules_reads.pop(0) if self.rules_reads else self.rules
            return copy.deepcopy(rules)

        if "/check-runs" in endpoint and method == "GET":
            return copy.deepcopy(self.evidence)

        if endpoint.endswith(f"/commits/{EVIDENCE_SHA}/pulls") and method == "GET":
            pull_requests = (
                self.pull_request_reads.pop(0)
                if self.pull_request_reads
                else self.pull_requests
            )
            return copy.deepcopy(pull_requests)

        if "/actions/runs/" in endpoint and method == "GET":
            run_id = int(endpoint.rsplit("/", 1)[-1])
            return copy.deepcopy(self.workflow_runs[run_id])

        if "/actions/jobs/" in endpoint and method == "GET":
            job_id = int(endpoint.rsplit("/", 1)[-1])
            return copy.deepcopy(self.jobs[job_id])

        raise AssertionError(f"unexpected gh call: {arguments}")

    @property
    def patch_calls(self) -> list[tuple[list[str], str | None]]:
        return [
            call
            for call in self.calls
            if "--method" in call[0]
            and call[0][call[0].index("--method") + 1] == "PATCH"
        ]


def test_default_plan_is_read_only() -> None:
    manifest = make_manifest()
    fake = FakeGitHub(make_policy(LEGACY_CONTEXTS))

    with patch.object(sync, "run_gh", side_effect=fake):
        inspection = sync.inspect_repository(REPOSITORY, manifest)
        document = sync.plan_document(inspection, manifest)

    assert document["state"] == "LEGACY"
    assert document["remote_mutation_required"] is True
    assert fake.patch_calls == []
    assert all(call[0][call[0].index("--method") + 1] == "GET" for call in fake.calls)


@pytest.mark.parametrize(
    "manifest_path",
    [
        Path("github-policy.json"),
        Path("governance/../governance/github-policy.json"),
        Path("/tmp/governance/github-policy.json"),
    ],
)
def test_apply_requires_canonical_repository_relative_manifest_path(
    manifest_path: Path,
    tmp_path: Path,
) -> None:
    fake = FakeGitHub(make_policy(LEGACY_CONTEXTS))

    with patch.object(sync, "run_gh", side_effect=fake):
        with pytest.raises(sync.GovernanceError, match="canonical repository-relative"):
            sync.apply_policy(
                REPOSITORY,
                make_manifest(),
                evidence_sha=EVIDENCE_SHA,
                snapshot_out=tmp_path / "snapshot.json",
                confirm_repository=REPOSITORY,
                manifest_path=manifest_path,
            )

    assert fake.calls == []


def test_apply_rejects_manifest_worktree_evidence_mismatch_before_remote_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sync, "read_working_manifest", lambda path: b"working")
    monkeypatch.setattr(sync, "read_manifest_blob", lambda revision, path: b"committed")
    fake = FakeGitHub(make_policy(LEGACY_CONTEXTS))

    with patch.object(sync, "run_gh", side_effect=fake):
        with pytest.raises(sync.GovernanceError, match="working tree differs"):
            sync.apply_policy(
                REPOSITORY,
                make_manifest(),
                evidence_sha=EVIDENCE_SHA,
                snapshot_out=tmp_path / "snapshot.json",
                confirm_repository=REPOSITORY,
            )

    assert fake.calls == []


def test_apply_rejects_loaded_manifest_object_not_bound_to_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    different = manifest_document()
    different["default_branch"] = "develop"
    manifest_bytes = json.dumps(different, sort_keys=True).encode("utf-8")
    monkeypatch.setattr(sync, "read_working_manifest", lambda path: manifest_bytes)
    monkeypatch.setattr(
        sync,
        "read_manifest_blob",
        lambda revision, path: manifest_bytes,
    )
    fake = FakeGitHub(make_policy(LEGACY_CONTEXTS))

    with patch.object(sync, "run_gh", side_effect=fake):
        with pytest.raises(sync.GovernanceError, match="loaded manifest does not match"):
            sync.apply_policy(
                REPOSITORY,
                make_manifest(),
                evidence_sha=EVIDENCE_SHA,
                snapshot_out=tmp_path / "snapshot.json",
                confirm_repository=REPOSITORY,
            )

    assert fake.calls == []


def test_apply_revalidates_manifest_binding_immediately_before_patch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_bytes = json.dumps(manifest_document(), sort_keys=True).encode("utf-8")
    working_reads = iter([manifest_bytes, b"changed after evidence collection"])
    monkeypatch.setattr(sync, "read_working_manifest", lambda path: next(working_reads))
    monkeypatch.setattr(
        sync,
        "read_manifest_blob",
        lambda revision, path: manifest_bytes,
    )
    fake = FakeGitHub(make_policy(LEGACY_CONTEXTS))
    snapshot = tmp_path / "snapshot.json"

    with patch.object(sync, "run_gh", side_effect=fake):
        with pytest.raises(sync.GovernanceError, match="working tree differs"):
            sync.apply_policy(
                REPOSITORY,
                make_manifest(),
                evidence_sha=EVIDENCE_SHA,
                snapshot_out=snapshot,
                confirm_repository=REPOSITORY,
            )

    assert fake.patch_calls == []
    assert snapshot.exists()


def test_legacy_apply_reaches_target_and_writes_verified_snapshot(tmp_path: Path) -> None:
    manifest = make_manifest()
    fake = FakeGitHub(make_policy(LEGACY_CONTEXTS))
    snapshot = tmp_path / "required-checks.snapshot.json"

    with patch.object(sync, "run_gh", side_effect=fake):
        result = sync.apply_policy(
            REPOSITORY,
            manifest,
            evidence_sha=EVIDENCE_SHA,
            snapshot_out=snapshot,
            confirm_repository=REPOSITORY,
        )

    assert result["changed"] is True
    assert result["state_before"] == "LEGACY"
    assert result["state_after"] == "TARGET"
    assert fake.policy == make_policy(TARGET_CONTEXTS)
    assert len(fake.patch_calls) == 1
    assert stat.S_IMODE(snapshot.stat().st_mode) == 0o600
    loaded = sync.load_snapshot(snapshot)
    assert loaded["canonical_sha256"].startswith("sha256:")
    assert loaded["repository"] == REPOSITORY


def test_target_apply_is_idempotent_and_does_not_write_snapshot(tmp_path: Path) -> None:
    manifest = make_manifest()
    fake = FakeGitHub(make_policy(TARGET_CONTEXTS))
    snapshot = tmp_path / "unused.snapshot.json"

    with patch.object(sync, "run_gh", side_effect=fake):
        result = sync.apply_policy(
            REPOSITORY,
            manifest,
            evidence_sha=EVIDENCE_SHA,
            snapshot_out=snapshot,
            confirm_repository=REPOSITORY,
        )

    assert result["changed"] is False
    assert fake.patch_calls == []
    assert not snapshot.exists()


@pytest.mark.parametrize(
    ("contexts", "expected_state"),
    [
        (STABLE_CONTEXTS | {"Validate bank-worker"}, "MIXED"),
        (STABLE_CONTEXTS | {"Unmanaged external check"}, "DIVERGED"),
        ({"Lint policy"} | RETIRED_CONTEXTS, "DIVERGED"),
    ],
)
def test_mixed_and_diverged_states_reject_apply(
    contexts: set[str], expected_state: str, tmp_path: Path
) -> None:
    manifest = make_manifest()
    fake = FakeGitHub(make_policy(contexts))

    with patch.object(sync, "run_gh", side_effect=fake):
        with pytest.raises(sync.GovernanceError, match=expected_state):
            sync.apply_policy(
                REPOSITORY,
                manifest,
                evidence_sha=EVIDENCE_SHA,
                snapshot_out=tmp_path / "snapshot.json",
                confirm_repository=REPOSITORY,
            )

    assert fake.patch_calls == []


def test_transition_state_is_reconcilable() -> None:
    manifest = make_manifest()
    transition = make_policy(TARGET_CONTEXTS | RETIRED_CONTEXTS)

    assessment = sync.assess_state(transition, manifest)

    assert assessment.state is sync.PolicyState.TRANSITION


@pytest.mark.parametrize("failure_kind", ["missing", "failed", "wrong-app"])
def test_apply_rejects_bad_check_run_evidence(
    failure_kind: str, tmp_path: Path
) -> None:
    manifest = make_manifest()
    evidence = success_evidence(TARGET_CONTEXTS)
    runs = evidence["check_runs"]
    assert isinstance(runs, list)
    target_context = sorted(TARGET_CONTEXTS)[0]
    target_run = next(run for run in runs if run["name"] == target_context)
    if failure_kind == "missing":
        runs.remove(target_run)
        expected = "missing CheckRun evidence"
    elif failure_kind == "failed":
        target_run["conclusion"] = "failure"
        expected = "not SUCCESS"
    else:
        target_run["app"] = {"id": 999, "slug": "untrusted-app"}
        expected = "wrong GitHub App"

    fake = FakeGitHub(make_policy(LEGACY_CONTEXTS), evidence=evidence)
    with patch.object(sync, "run_gh", side_effect=fake):
        with pytest.raises(sync.GovernanceError, match=expected):
            sync.apply_policy(
                REPOSITORY,
                manifest,
                evidence_sha=EVIDENCE_SHA,
                snapshot_out=tmp_path / "snapshot.json",
                confirm_repository=REPOSITORY,
            )

    assert fake.patch_calls == []
    assert not (tmp_path / "snapshot.json").exists()


@pytest.mark.parametrize(
    "pull_requests",
    [
        [],
        [pull_request(head_sha="b" * 40)],
        [pull_request(base_ref="develop")],
        [pull_request(), pull_request(number=4)],
    ],
    ids=["not-a-pr", "stale-head", "wrong-base", "ambiguous-prs"],
)
def test_apply_rejects_sha_without_exactly_one_current_target_pr(
    pull_requests: list[dict[str, object]], tmp_path: Path
) -> None:
    fake = FakeGitHub(
        make_policy(LEGACY_CONTEXTS),
        pull_requests=pull_requests,
    )

    with patch.object(sync, "run_gh", side_effect=fake):
        with pytest.raises(sync.GovernanceError, match="exactly one open pull request"):
            sync.apply_policy(
                REPOSITORY,
                make_manifest(),
                evidence_sha=EVIDENCE_SHA,
                snapshot_out=tmp_path / "snapshot.json",
                confirm_repository=REPOSITORY,
            )

    assert fake.patch_calls == []
    assert not (tmp_path / "snapshot.json").exists()


@pytest.mark.parametrize(
    ("failure_kind", "expected"),
    [
        ("malformed-details-url", "details_url"),
        ("wrong-check-pr", "CheckRun.*pull request"),
        ("wrong-workflow", "workflow path"),
        ("wrong-event", "pull_request event"),
        ("wrong-head", "workflow run.*head SHA"),
        ("wrong-workflow-pr", "workflow run.*pull request"),
        ("wrong-job-run", "job.*workflow run"),
    ],
)
def test_apply_rejects_alternate_or_malformed_actions_provenance(
    failure_kind: str, expected: str, tmp_path: Path
) -> None:
    evidence = success_evidence(TARGET_CONTEXTS)
    runs = evidence["check_runs"]
    assert isinstance(runs, list)
    target_run = runs[0]
    workflow_runs = {WORKFLOW_RUN_ID: success_workflow_run()}
    jobs = success_jobs(TARGET_CONTEXTS)

    if failure_kind == "malformed-details-url":
        target_run["details_url"] = "https://attacker.example/actions/runs/7001/job/8001"
    elif failure_kind == "wrong-check-pr":
        target_run["pull_requests"] = [pull_request_association(number=99)]
    elif failure_kind == "wrong-workflow":
        workflow_runs[WORKFLOW_RUN_ID]["path"] = ".github/workflows/other.yml@main"
    elif failure_kind == "wrong-event":
        workflow_runs[WORKFLOW_RUN_ID]["event"] = "workflow_dispatch"
    elif failure_kind == "wrong-head":
        workflow_runs[WORKFLOW_RUN_ID]["head_sha"] = "b" * 40
    elif failure_kind == "wrong-workflow-pr":
        workflow_runs[WORKFLOW_RUN_ID]["pull_requests"] = [
            pull_request_association(number=99)
        ]
    else:
        details_url = target_run["details_url"]
        assert isinstance(details_url, str)
        job_id = int(details_url.rsplit("/", 1)[-1])
        jobs[job_id]["run_id"] = WORKFLOW_RUN_ID + 1

    fake = FakeGitHub(
        make_policy(LEGACY_CONTEXTS),
        evidence=evidence,
        workflow_runs=workflow_runs,
        jobs=jobs,
    )
    snapshot = tmp_path / "snapshot.json"
    with patch.object(sync, "run_gh", side_effect=fake):
        with pytest.raises(sync.GovernanceError, match=expected):
            sync.apply_policy(
                REPOSITORY,
                make_manifest(),
                evidence_sha=EVIDENCE_SHA,
                snapshot_out=snapshot,
                confirm_repository=REPOSITORY,
            )

    assert fake.patch_calls == []
    assert not snapshot.exists()


def test_evidence_accepts_current_pr_provenance_and_caches_workflow_run() -> None:
    manifest = make_manifest()
    fake = FakeGitHub(make_policy(LEGACY_CONTEXTS))

    with patch.object(sync, "run_gh", side_effect=fake):
        app_ids = sync.collect_evidence_app_ids(REPOSITORY, EVIDENCE_SHA, manifest)

    assert app_ids == {context: APP_ID for context in TARGET_CONTEXTS}
    workflow_reads = [
        call
        for call in fake.calls
        if "/actions/runs/" in next(
            item for item in call[0] if item.startswith("repos/")
        )
    ]
    assert len(workflow_reads) == 1


def test_apply_rejects_offline_job_mapping_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        sync,
        "read_git_blob",
        lambda revision, path: (
            "name: Policy workflow\n"
            "on:\n"
            "  pull_request:\n"
            "jobs:\n"
            "  unrelated_job:\n"
            "    name: Unrelated context\n"
        ),
    )
    fake = FakeGitHub(make_policy(LEGACY_CONTEXTS))

    with patch.object(sync, "run_gh", side_effect=fake):
        with pytest.raises(sync.GovernanceError, match="offline workflow mapping"):
            sync.apply_policy(
                REPOSITORY,
                make_manifest(),
                evidence_sha=EVIDENCE_SHA,
                snapshot_out=tmp_path / "snapshot.json",
                confirm_repository=REPOSITORY,
            )

    assert fake.patch_calls == []


def test_apply_aborts_on_optimistic_concurrency_drift(tmp_path: Path) -> None:
    manifest = make_manifest()
    legacy = make_policy(LEGACY_CONTEXTS)
    concurrent = make_policy(TARGET_CONTEXTS | RETIRED_CONTEXTS)
    fake = FakeGitHub(legacy, policy_reads=[legacy, concurrent])

    with patch.object(sync, "run_gh", side_effect=fake):
        with pytest.raises(sync.GovernanceError, match="changed concurrently"):
            sync.apply_policy(
                REPOSITORY,
                manifest,
                evidence_sha=EVIDENCE_SHA,
                snapshot_out=tmp_path / "snapshot.json",
                confirm_repository=REPOSITORY,
            )

    assert fake.patch_calls == []
    assert not (tmp_path / "snapshot.json").exists()


@pytest.mark.parametrize(
    "second_pull_requests",
    [
        [pull_request(head_sha="b" * 40)],
        [pull_request(number=4)],
    ],
    ids=["stale-head", "different-pr"],
)
def test_apply_revalidates_exact_pull_request_identity_before_patch(
    second_pull_requests: list[dict[str, object]], tmp_path: Path,
) -> None:
    manifest = make_manifest()
    legacy = make_policy(LEGACY_CONTEXTS)
    fake = FakeGitHub(
        legacy,
        pull_request_reads=[
            [pull_request()],
            second_pull_requests,
        ],
    )

    with patch.object(sync, "run_gh", side_effect=fake):
        with pytest.raises(sync.GovernanceError, match="evidence pull request changed"):
            sync.apply_policy(
                REPOSITORY,
                manifest,
                evidence_sha=EVIDENCE_SHA,
                snapshot_out=tmp_path / "snapshot.json",
                confirm_repository=REPOSITORY,
            )

    assert fake.patch_calls == []
    assert not (tmp_path / "snapshot.json").exists()


def test_apply_revalidates_pull_request_after_snapshot_immediately_before_patch(
    tmp_path: Path,
) -> None:
    manifest = make_manifest()
    legacy = make_policy(LEGACY_CONTEXTS)
    snapshot = tmp_path / "snapshot.json"
    fake = FakeGitHub(
        legacy,
        pull_request_reads=[
            [pull_request()],
            [pull_request()],
            [pull_request(head_sha="b" * 40)],
        ],
    )

    with patch.object(sync, "run_gh", side_effect=fake):
        with pytest.raises(sync.GovernanceError, match="evidence pull request changed"):
            sync.apply_policy(
                REPOSITORY,
                manifest,
                evidence_sha=EVIDENCE_SHA,
                snapshot_out=snapshot,
                confirm_repository=REPOSITORY,
            )

    assert fake.patch_calls == []
    assert snapshot.exists()


def test_apply_rechecks_policy_after_snapshot_immediately_before_patch(
    tmp_path: Path,
) -> None:
    manifest = make_manifest()
    legacy = make_policy(LEGACY_CONTEXTS)
    concurrent = make_policy(TARGET_CONTEXTS | RETIRED_CONTEXTS)
    snapshot = tmp_path / "snapshot.json"
    fake = FakeGitHub(
        legacy,
        policy_reads=[legacy, legacy, concurrent],
    )

    with patch.object(sync, "run_gh", side_effect=fake):
        with pytest.raises(sync.GovernanceError, match="changed concurrently"):
            sync.apply_policy(
                REPOSITORY,
                manifest,
                evidence_sha=EVIDENCE_SHA,
                snapshot_out=snapshot,
                confirm_repository=REPOSITORY,
            )

    assert fake.patch_calls == []
    assert snapshot.exists()


def test_apply_aborts_when_effective_rulesets_are_active(tmp_path: Path) -> None:
    manifest = make_manifest()
    fake = FakeGitHub(
        make_policy(LEGACY_CONTEXTS),
        rules=[{"type": "required_status_checks", "ruleset_source_type": "Repository"}],
    )

    with patch.object(sync, "run_gh", side_effect=fake):
        with pytest.raises(sync.GovernanceError, match="rulesets"):
            sync.apply_policy(
                REPOSITORY,
                manifest,
                evidence_sha=EVIDENCE_SHA,
                snapshot_out=tmp_path / "snapshot.json",
                confirm_repository=REPOSITORY,
            )

    assert fake.patch_calls == []


def test_failed_post_apply_verification_triggers_automatic_rollback(
    tmp_path: Path,
) -> None:
    manifest = make_manifest()
    legacy = make_policy(LEGACY_CONTEXTS)
    wrong_readback = make_policy(STABLE_CONTEXTS | {"Microservices validation gate"}, strict=False)
    target = make_policy(TARGET_CONTEXTS)
    fake = FakeGitHub(
        legacy,
        policy_reads=[
            legacy,
            legacy,
            legacy,
            wrong_readback,
            target,
            target,
            legacy,
        ],
    )

    with patch.object(sync, "run_gh", side_effect=fake):
        with pytest.raises(sync.GovernanceError, match="automatic rollback restored"):
            sync.apply_policy(
                REPOSITORY,
                manifest,
                evidence_sha=EVIDENCE_SHA,
                snapshot_out=tmp_path / "snapshot.json",
                confirm_repository=REPOSITORY,
            )

    assert len(fake.patch_calls) == 2
    assert fake.policy == legacy


def test_post_patch_third_party_drift_is_never_overwritten(tmp_path: Path) -> None:
    manifest = make_manifest()
    legacy = make_policy(LEGACY_CONTEXTS)
    concurrent = make_policy(
        TARGET_CONTEXTS | {"Independent security gate"},
    )
    fake = FakeGitHub(
        legacy,
        policy_reads=[legacy, legacy, legacy, concurrent, concurrent],
    )

    with patch.object(sync, "run_gh", side_effect=fake):
        with pytest.raises(sync.GovernanceError, match="remote drift.*not compensated"):
            sync.apply_policy(
                REPOSITORY,
                manifest,
                evidence_sha=EVIDENCE_SHA,
                snapshot_out=tmp_path / "snapshot.json",
                confirm_repository=REPOSITORY,
            )

    assert len(fake.patch_calls) == 1


def test_drift_between_recovery_reads_aborts_before_compensation(
    tmp_path: Path,
) -> None:
    manifest = make_manifest()
    legacy = make_policy(LEGACY_CONTEXTS)
    target = make_policy(TARGET_CONTEXTS)
    wrong_readback = make_policy(TARGET_CONTEXTS, strict=False)
    concurrent = make_policy(TARGET_CONTEXTS | {"Independent security gate"})
    fake = FakeGitHub(
        legacy,
        policy_reads=[legacy, legacy, legacy, wrong_readback, target, concurrent],
    )

    with patch.object(sync, "run_gh", side_effect=fake):
        with pytest.raises(
            sync.GovernanceError,
            match="drift was detected before compensation.*not compensated",
        ):
            sync.apply_policy(
                REPOSITORY,
                manifest,
                evidence_sha=EVIDENCE_SHA,
                snapshot_out=tmp_path / "snapshot.json",
                confirm_repository=REPOSITORY,
            )

    assert len(fake.patch_calls) == 1


@pytest.mark.parametrize(
    ("committed_before_timeout", "policy_after_timeout", "expected", "patch_count"),
    [
        (True, make_policy(TARGET_CONTEXTS), "automatic rollback restored", 2),
        (False, make_policy(LEGACY_CONTEXTS), "original policy remains", 1),
        (
            False,
            make_policy(TARGET_CONTEXTS | {"Independent security gate"}),
            "remote drift.*not compensated",
            1,
        ),
    ],
    ids=["committed", "not-committed", "third-party-drift"],
)
def test_patch_timeout_uses_safe_readback_before_compensation(
    committed_before_timeout: bool,
    policy_after_timeout: sync.RequiredStatusPolicy,
    expected: str,
    patch_count: int,
    tmp_path: Path,
) -> None:
    manifest = make_manifest()
    legacy = make_policy(LEGACY_CONTEXTS)
    target = make_policy(TARGET_CONTEXTS)
    policy_reads: list[sync.RequiredStatusPolicy | Exception] = [
        legacy,
        legacy,
        legacy,
        policy_after_timeout,
    ]
    if committed_before_timeout:
        policy_reads.extend([target, legacy])
    fake = FakeGitHub(
        legacy,
        policy_reads=policy_reads,
        patch_failures=[
            (
                committed_before_timeout,
                sync.GovernanceError("simulated PATCH response timeout"),
            )
        ],
    )

    with patch.object(sync, "run_gh", side_effect=fake):
        with pytest.raises(sync.GovernanceError, match=expected):
            sync.apply_policy(
                REPOSITORY,
                manifest,
                evidence_sha=EVIDENCE_SHA,
                snapshot_out=tmp_path / "snapshot.json",
                confirm_repository=REPOSITORY,
            )

    assert len(fake.patch_calls) == patch_count
    if committed_before_timeout:
        assert fake.policy == legacy


def test_unknown_patch_outcome_without_readback_never_compensates(
    tmp_path: Path,
) -> None:
    manifest = make_manifest()
    legacy = make_policy(LEGACY_CONTEXTS)
    fake = FakeGitHub(
        legacy,
        policy_reads=[
            legacy,
            legacy,
            legacy,
            sync.GovernanceError("simulated recovery read timeout"),
        ],
        patch_failures=[
            (True, sync.GovernanceError("simulated PATCH response timeout"))
        ],
    )

    with patch.object(sync, "run_gh", side_effect=fake):
        with pytest.raises(sync.GovernanceError, match="outcome is unknown.*not attempted"):
            sync.apply_policy(
                REPOSITORY,
                manifest,
                evidence_sha=EVIDENCE_SHA,
                snapshot_out=tmp_path / "snapshot.json",
                confirm_repository=REPOSITORY,
            )

    assert len(fake.patch_calls) == 1


def test_explicit_rollback_restores_snapshot_state(tmp_path: Path) -> None:
    manifest = make_manifest()
    before = make_policy(LEGACY_CONTEXTS)
    after = make_policy(TARGET_CONTEXTS)
    snapshot = tmp_path / "snapshot.json"
    sync.write_snapshot(snapshot, REPOSITORY, BRANCH, before, after)
    fake = FakeGitHub(after)

    with patch.object(sync, "run_gh", side_effect=fake):
        result = sync.rollback_policy(
            REPOSITORY,
            manifest,
            snapshot_in=snapshot,
            confirm_repository=REPOSITORY,
        )

    assert result["changed"] is True
    assert result["restored"] is True
    assert fake.policy == before
    assert len(fake.patch_calls) == 1


def test_rollback_never_rolls_forward_over_third_party_drift(
    tmp_path: Path,
) -> None:
    manifest = make_manifest()
    before = make_policy(LEGACY_CONTEXTS)
    after = make_policy(TARGET_CONTEXTS)
    concurrent = make_policy(TARGET_CONTEXTS | {"Independent security gate"})
    snapshot = tmp_path / "snapshot.json"
    sync.write_snapshot(snapshot, REPOSITORY, BRANCH, before, after)
    fake = FakeGitHub(
        after,
        policy_reads=[after, after, concurrent, concurrent],
    )

    with patch.object(sync, "run_gh", side_effect=fake):
        with pytest.raises(sync.GovernanceError, match="remote drift.*not compensated"):
            sync.rollback_policy(
                REPOSITORY,
                manifest,
                snapshot_in=snapshot,
                confirm_repository=REPOSITORY,
            )

    assert len(fake.patch_calls) == 1


def test_rollback_timeout_compensates_only_after_exact_safe_readback(
    tmp_path: Path,
) -> None:
    manifest = make_manifest()
    before = make_policy(LEGACY_CONTEXTS)
    after = make_policy(TARGET_CONTEXTS)
    snapshot = tmp_path / "snapshot.json"
    sync.write_snapshot(snapshot, REPOSITORY, BRANCH, before, after)
    fake = FakeGitHub(
        after,
        policy_reads=[after, after, before, before, after],
        patch_failures=[
            (True, sync.GovernanceError("simulated rollback PATCH timeout"))
        ],
    )

    with patch.object(sync, "run_gh", side_effect=fake):
        with pytest.raises(sync.GovernanceError, match="compensating roll-forward restored"):
            sync.rollback_policy(
                REPOSITORY,
                manifest,
                snapshot_in=snapshot,
                confirm_repository=REPOSITORY,
            )

    assert len(fake.patch_calls) == 2
    assert fake.policy == after


def test_snapshot_tampering_is_rejected(tmp_path: Path) -> None:
    before = make_policy(LEGACY_CONTEXTS)
    after = make_policy(TARGET_CONTEXTS)
    snapshot = tmp_path / "snapshot.json"
    sync.write_snapshot(snapshot, REPOSITORY, BRANCH, before, after)
    document = json.loads(snapshot.read_text(encoding="utf-8"))
    document["repository"] = "attacker/other-repository"
    snapshot.write_text(json.dumps(document), encoding="utf-8")
    snapshot.chmod(0o600)

    with pytest.raises(sync.GovernanceError, match="SHA-256"):
        sync.load_snapshot(snapshot)


def test_manifest_requires_string_schema_version(tmp_path: Path) -> None:
    manifest_path = tmp_path / "github-policy.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": "1",
                "scope": "repository",
                "default_branch": BRANCH,
                "required_status_checks": {
                    "strict": True,
                    "expected_app_slug": APP_SLUG,
                    "checks": [
                        {
                            "context": "Microservices validation gate",
                            "workflow": ".github/workflows/microservices-build.yml",
                            "job": "gate",
                        }
                    ],
                },
                "migration": {
                    "added_contexts": ["Microservices validation gate"],
                    "retired_contexts": ["Validate old-service"],
                },
            }
        ),
        encoding="utf-8",
    )

    manifest = sync.load_manifest(manifest_path)

    assert manifest.schema_version == "1"


def test_repository_manifest_matches_reconciler_contract() -> None:
    manifest = sync.load_manifest(REPO_ROOT / "governance" / "github-policy.json")

    assert manifest.schema_version == "1"
    assert manifest.default_branch == "main"
    assert manifest.added_contexts <= manifest.target_contexts
    assert not (manifest.retired_contexts & manifest.target_contexts)


def canonical_manifest_document() -> dict[str, object]:
    return {
        "$schema": "../schemas/github-policy.schema.json",
        "schema_version": "1",
        "scope": "repository",
        "default_branch": BRANCH,
        "required_status_checks": {
            "strict": True,
            "expected_app_slug": APP_SLUG,
            "checks": [
                {
                    "context": "Microservices validation gate",
                    "workflow": ".github/workflows/microservices-build.yml",
                    "job": "validation_gate",
                }
            ],
        },
        "migration": {
            "added_contexts": ["Microservices validation gate"],
            "retired_contexts": ["Validate old-service"],
        },
    }


@pytest.mark.parametrize("scope", [None, "organization", "Repository"])
def test_manifest_requires_exact_repository_scope(tmp_path: Path, scope: str | None) -> None:
    document = canonical_manifest_document()
    if scope is None:
        document.pop("scope")
    else:
        document["scope"] = scope
    manifest_path = tmp_path / "github-policy.json"
    manifest_path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(sync.GovernanceError, match="scope"):
        sync.load_manifest(manifest_path)


@pytest.mark.parametrize("location", ["root", "required", "migration", "check"])
def test_manifest_rejects_unknown_keys(tmp_path: Path, location: str) -> None:
    document = canonical_manifest_document()
    if location == "root":
        document["unexpected"] = True
    elif location == "required":
        required = document["required_status_checks"]
        assert isinstance(required, dict)
        required["unexpected"] = True
    elif location == "migration":
        migration = document["migration"]
        assert isinstance(migration, dict)
        migration["unexpected"] = True
    else:
        required = document["required_status_checks"]
        assert isinstance(required, dict)
        checks = required["checks"]
        assert isinstance(checks, list)
        checks[0]["unexpected"] = True
    manifest_path = tmp_path / "github-policy.json"
    manifest_path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(sync.GovernanceError, match="unknown keys"):
        sync.load_manifest(manifest_path)


def test_manifest_rejects_dynamic_required_contexts(tmp_path: Path) -> None:
    document = canonical_manifest_document()
    required = document["required_status_checks"]
    migration = document["migration"]
    assert isinstance(required, dict) and isinstance(migration, dict)
    checks = required["checks"]
    assert isinstance(checks, list)
    dynamic = "Validate ${{ matrix.service }}"
    checks[0]["context"] = dynamic
    migration["added_contexts"] = [dynamic]
    manifest_path = tmp_path / "github-policy.json"
    manifest_path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(sync.GovernanceError, match="static check context"):
        sync.load_manifest(manifest_path)
