from tooling.platform_authority_lambda_invocation_authority import _resource_policy_edges
from tests.test_deployment.test_gug218_lambda_invocation_authority import _binding, _allowlist

binding = _binding()
statement = {
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::111122223333:role/Synthetic"},
    "Action": "lambda:*",
    "Resource": "arn:aws:lambda:us-east-1:111122223333:function:target:${aws:username}"
}
policy = {
    "resource_arn": binding.function_arn,
    "policy_document": {
        "Version": "2012-10-17",
        "Statement": [statement]
    }
}

try:
    print(_resource_policy_edges(binding, _allowlist(), [policy]))
except Exception as e:
    import traceback
    traceback.print_exc()
