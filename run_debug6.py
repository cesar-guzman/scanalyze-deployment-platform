from tests.test_deployment.test_gug218_lambda_invocation_authority import _binding, _snapshot, _analyze
from tooling.platform_authority_lambda_invocation_authority import canonical_digest, _seal_raw_snapshot

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
inventory, receipt = _analyze(snapshot)
print("INVENTORY STATUS:", inventory["status"])
print(receipt)
