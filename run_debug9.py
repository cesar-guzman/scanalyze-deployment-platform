from tooling.platform_authority_lambda_invocation_authority import analyze_authority_inventory, _seal_raw_snapshot
from tests.test_deployment.test_gug218_lambda_invocation_authority import _binding, _snapshot, _allowlist

snapshot = _snapshot()
ACCOUNT = "111122223333"
statement = {
    "Effect": "Allow",
    "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:role/Synthetic"},
    "Action": "lambda:*",
    "Resource": _binding().function_arn
}
injected_document = {
    "Version": "2012-10-17",
    "Statement": [statement]
}
snapshot["lambda"]["resource_policies"].append({
    "resource_arn": _binding().function_arn,
    "policy_document": injected_document
})

snapshot = _seal_raw_snapshot(snapshot)

try:
    inventory, receipt = analyze_authority_inventory(
        allowlist=_allowlist(),
        snapshot=snapshot,
        binding=_binding(),
        evidence_source_mode="AWS_READ_ONLY",
        decision_at="2030-01-01T00:01:01Z",
    )
    print("STATUS:", inventory["status"])
    print("UNSUPPORTED:", inventory["unsupported_policy_semantics_detected"])
    print("PROHIBITED:", inventory["prohibited_edge_count"])
    print("UNKNOWN:", inventory["unknown_edge_count"])
    print("COVERAGE:", inventory["coverage"])
except Exception as e:
    import traceback
    traceback.print_exc()
