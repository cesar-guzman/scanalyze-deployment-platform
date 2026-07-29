import pytest

def test_gug264_baseline_helper_reproduction() -> None:
    from tooling.platform_authority_lambda_invocation_authority import _resource_policy_edges
    from tests.test_deployment.test_gug218_lambda_invocation_authority import _binding, _allowlist
    
    binding = _binding()
    allowlist = _allowlist()
    
    # We want to show that currently, a malformed statement is skipped (returns no edges and unsupported=False).
    # After the fix, unsupported will be True.
    # The statement has a wildcard action, and a malformed resource.
    
    malformed_resources = [
        "arn:aws:lambda:us-east-1:111122223333:function:target:${aws:username}", # variable
        "arn:aws:lambda", # incomplete
        "foo:aws:lambda:us-east-1:111122223333:function:x", # invalid prefix
        " arn:aws:lambda:us-east-1:111122223333:function:x", # whitespace
    ]
    
    # Actually, we shouldn't assert on pre-fix behavior because after we fix it, the test will fail!
    # Wait, the prompt says "Write focused regression tests before changing production code... 
    # The pre-fix integration behavior must demonstrate that at least one malformed statement is skipped without setting unsupported."
    # How do we write a permanent regression test if it expects the old behavior?
    # Usually, a regression test asserts the *new* expected behavior (i.e. unsupported=True). I will assert the NEW expected behavior.
    
    for res in malformed_resources:
        statement = {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::111122223333:role/Synthetic"},
            "Action": "lambda:*",
            "Resource": res
        }
        policy = {
            "resource_arn": binding.function_arn,
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [statement]
            }
        }
        
        edges, unsupported = _resource_policy_edges(binding, allowlist, [policy])
        assert unsupported is True, f"Expected unsupported=True for resource: {res}"
        assert len(edges) == 0
        
    # Both Resource and NotResource
    statement = {
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::111122223333:role/Synthetic"},
        "Action": "lambda:*",
        "Resource": "arn:aws:lambda:us-east-1:111122223333:function:x",
        "NotResource": "arn:aws:lambda:us-east-1:111122223333:function:y"
    }
    policy = {
        "resource_arn": binding.function_arn,
        "policy_document": {
            "Version": "2012-10-17",
            "Statement": [statement]
        }
    }
    edges, unsupported = _resource_policy_edges(binding, allowlist, [policy])
    assert unsupported is True
    assert len(edges) == 0

    # Neither Resource nor NotResource
    statement = {
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::111122223333:role/Synthetic"},
        "Action": "lambda:*"
    }
    policy = {
        "resource_arn": binding.function_arn,
        "policy_document": {
            "Version": "2012-10-17",
            "Statement": [statement]
        }
    }
    edges, unsupported = _resource_policy_edges(binding, allowlist, [policy])
    assert unsupported is True
    assert len(edges) == 0
