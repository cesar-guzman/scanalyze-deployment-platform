code = """
def test_gug264_baseline_helper_reproduction() -> None:
    from tooling.platform_authority_lambda_invocation_authority import _resource_policy_edges
    
    binding = _binding()
    allowlist = {"AuthorityInventoryExpectedEdges": []}
    
    malformed_resources = [
        "arn:aws:lambda:us-east-1:111122223333:function:target:${aws:username}",
        "arn:aws:lambda",
        "foo:aws:lambda:us-east-1:111122223333:function:x",
        " arn:aws:lambda:us-east-1:111122223333:function:x",
    ]
    
    for res in malformed_resources:
        statement = {
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:role/Synthetic"},
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
        
    statement = {
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:role/Synthetic"},
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

    statement = {
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:role/Synthetic"},
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

def test_gug264_full_analyzer_integration_reproduction() -> None:
    from tooling.platform_authority_lambda_invocation_authority import canonical_digest
    
    snapshot = _snapshot()
    statement = {
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:role/Synthetic"},
        "Action": "lambda:*",
        "Resource": "arn:aws:lambda:us-east-1:111122223333:function:target:${aws:username}"
    }
    injected_document = {
        "Version": "2012-10-17",
        "Statement": [statement]
    }
    injected_digest = canonical_digest(injected_document)
    
    # Inject into lambda resource policy
    snapshot["lambda"]["functions"][0]["resource_policies"].append({
        "resource_arn": _binding().function_arn,
        "policy_document": injected_document
    })
    
    inventory, receipt = _analyze(snapshot)
    
    assert inventory["status"] == INVENTORY_FOREIGN_AUTHORITY
    assert inventory["unsupported_policy_semantics_detected"] is True
    assert receipt["status"] == RECEIPT_UNSAFE
    
    # no exact allowlist-eligible edge comes from the injected document
    for edge in inventory["authority_edges"]:
        if edge["source_document_digest"] == injected_digest:
            assert edge["verdict"] != "EXPECTED_ALLOWLIST_EDGE"

def test_gug264_valid_unrelated_resource_control() -> None:
    snapshot = _snapshot()
    statement = {
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:role/Synthetic"},
        "Action": "lambda:*",
        "Resource": "arn:aws:lambda:us-east-1:111122223333:function:unrelated"
    }
    injected_document = {
        "Version": "2012-10-17",
        "Statement": [statement]
    }
    
    snapshot["lambda"]["functions"][0]["resource_policies"].append({
        "resource_arn": _binding().function_arn,
        "policy_document": injected_document
    })
    
    inventory, receipt = _analyze(snapshot)
    
    # baseline review-safe state remains unchanged
    assert inventory["status"] == INVENTORY_REVIEW_SAFE
    assert inventory["unsupported_policy_semantics_detected"] is False

def test_gug264_valid_attached_target_control() -> None:
    from tooling.platform_authority_lambda_invocation_authority import canonical_digest
    snapshot = _snapshot()
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
    injected_digest = canonical_digest(injected_document)
    
    snapshot["lambda"]["functions"][0]["resource_policies"].append({
        "resource_arn": _binding().function_arn,
        "policy_document": injected_document
    })
    
    inventory, receipt = _analyze(snapshot)
    
    assert inventory["status"] == INVENTORY_FOREIGN_AUTHORITY
    assert receipt["status"] == RECEIPT_UNSAFE
    assert any(
        edge["action_class"] == "WILDCARD" and edge["verdict"] == "PROHIBITED"
        and edge["source_document_digest"] == injected_digest
        for edge in inventory["authority_edges"]
    )

def test_gug264_not_resource_tests() -> None:
    from tooling.platform_authority_lambda_invocation_authority import _resource_policy_edges
    
    binding = _binding()
    allowlist = {"AuthorityInventoryExpectedEdges": []}
    
    # NotResource excludes attached resource -> statement does not apply (valid)
    statement = {
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:role/Synthetic"},
        "Action": "lambda:*",
        "NotResource": binding.function_arn
    }
    policy = {
        "resource_arn": binding.function_arn,
        "policy_document": {
            "Version": "2012-10-17",
            "Statement": [statement]
        }
    }
    edges, unsupported = _resource_policy_edges(binding, allowlist, [policy])
    assert unsupported is False
    assert len(edges) == 0

    # NotResource excludes unrelated resource -> statement applies and remains prohibited
    statement = {
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:role/Synthetic"},
        "Action": "lambda:*",
        "NotResource": "arn:aws:lambda:us-east-1:111122223333:function:unrelated"
    }
    policy = {
        "resource_arn": binding.function_arn,
        "policy_document": {
            "Version": "2012-10-17",
            "Statement": [statement]
        }
    }
    edges, unsupported = _resource_policy_edges(binding, allowlist, [policy])
    assert unsupported is False
    assert len(edges) > 0
    assert any(edge["action_class"] == "WILDCARD" for edge in edges)

    # NotResource contains policy variable -> unsupported
    statement = {
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:role/Synthetic"},
        "Action": "lambda:*",
        "NotResource": "arn:aws:lambda:us-east-1:111122223333:function:target:${aws:username}"
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
"""

with open("tests/test_deployment/test_gug218_lambda_invocation_authority.py", "a") as f:
    f.write(code)
