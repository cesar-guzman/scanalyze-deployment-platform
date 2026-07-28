
class TestGUG218CorrectivePass:
    def test_strict_action_syntax_rejects_whitespace_and_malformed(self) -> None:
        from tooling.platform_authority_lambda_invocation_authority import (
            AuthorityInventoryError,
            _classify_action_statement,
        )
        invalid_actions = [
            " lambda:InvokeFunction",
            "lambda:InvokeFunction ",
            "lambda: InvokeFunction",
            "lambda :InvokeFunction",
            "lambda:Invoke Function",
            "lambda\t:InvokeFunction",
            "foo:bar:baz",
            "lambda",
            ":*",
            "lambda:",
        ]
        for action in invalid_actions:
            with pytest.raises(AuthorityInventoryError, match="POLICY_ACTION_SEMANTICS_UNSUPPORTED"):
                _classify_action_statement({"Action": action})

    def test_validated_resource_patterns_rejects_malformed_arns(self) -> None:
        from tooling.platform_authority_lambda_invocation_authority import (
            AuthorityInventoryError,
            _validated_resource_patterns,
        )
        invalid_resources = [
            "not-an-arn",
            "foo:aws:lambda:us-east-1:111122223333:function:x",
            "arn::lambda:us-east-1:111122223333:function:x",
            "arn:aws::us-east-1:111122223333:function:x",
            "arn:aws:lambda:us-east-1:111122223333:function:",
            "arn:aws:lambda:us-east-1:111122223333:",
            "arn:aws:lambda",
            " arn:aws:lambda:us-east-1:111122223333:function:x",
            "arn:aws:lambda:us-east-1:111122223333:function:x ",
        ]
        for resource in invalid_resources:
            with pytest.raises(AuthorityInventoryError, match="POLICY_RESOURCE_ARN_INCOMPLETE"):
                _validated_resource_patterns({"Resource": resource})

    def test_validated_resource_patterns_rejects_mutual_exclusion_violation(self) -> None:
        from tooling.platform_authority_lambda_invocation_authority import (
            AuthorityInventoryError,
            _validated_resource_patterns,
        )
        with pytest.raises(AuthorityInventoryError, match="POLICY_RESOURCE_SEMANTICS_UNSUPPORTED"):
            _validated_resource_patterns({"Resource": "*", "NotResource": "*"})
        with pytest.raises(AuthorityInventoryError, match="POLICY_RESOURCE_SEMANTICS_UNSUPPORTED"):
            _validated_resource_patterns({"Action": "lambda:InvokeFunction"})

    @pytest.mark.parametrize(
        "qualifier",
        ("future-alias", "99", "$LATEST", "deleted-alias")
    )
    def test_latent_exact_qualifier_is_target_applicable(self, qualifier: str) -> None:
        from tooling.platform_authority_lambda_invocation_authority import _target_applicable
        from tests.test_deployment.test_gug218_lambda_invocation_authority import _binding
        binding = _binding()
        resource = f"{binding.function_arn}:{qualifier}"
        # A latent qualifier in a Resource block is applicable
        assert _target_applicable({"Resource": resource}, binding, []) is True
        # But an unrelated function qualifier is not applicable
        assert _target_applicable({"Resource": "arn:aws:lambda:us-east-1:111122223333:function:other:alias"}, binding, []) is False

    @pytest.mark.parametrize(
        "statement",
        (
            {"NotResource": "arn:aws:lambda:us-east-1:111122223333:function:target:future"},
            {"NotResource": ["arn:aws:lambda:us-east-1:111122223333:function:target", "arn:aws:lambda:us-east-1:111122223333:function:target:*"]},
            {"NotResource": "arn:aws:lambda:us-east-1:111122223333:function:foreign"},
        )
    )
    def test_not_resource_retains_complement_semantics_without_latent_candidates(self, statement: dict) -> None:
        from tooling.platform_authority_lambda_invocation_authority import _target_applicable
        from tests.test_deployment.test_gug218_lambda_invocation_authority import _binding
        binding = _binding()
        # Ensure that NotResource correctly uses complement semantics.
        # It's applicable if ANY candidate (target, target:*, invocation_resources) is NOT in the excluded set.
        assert _target_applicable(statement, binding, []) is True
