from tooling.platform_authority_lambda_invocation_authority import _classify_action_statement
statement = {
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::111122223333:role/Synthetic"},
    "Action": "lambda:*",
    "Resource": "arn:aws:lambda:us-east-1:111122223333:function:target"
}
cls = _classify_action_statement(statement)
print("not_action:", cls.not_action_present)
print("unknown_auth:", cls.unknown_authority_present)
print("wildcard:", cls.wildcard_present)
print("mutations:", cls.authority_mutations)
print("invocations:", cls.invocations)
