from tooling.platform_authority_lambda_invocation_authority import _validated_resource_patterns

statement = {
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::111122223333:role/Synthetic"},
    "Action": "lambda:*",
    "Resource": "arn:aws:lambda:us-east-1:111122223333:function:target"
}

try:
    print(_validated_resource_patterns(statement))
except Exception as e:
    import traceback
    traceback.print_exc()
