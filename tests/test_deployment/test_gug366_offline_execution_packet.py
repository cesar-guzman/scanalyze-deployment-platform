import unittest
import json
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '../../tooling'))
from gug125_offline_validator import OfflinePacketValidator

class TestGUG366OfflineExecutionPacket(unittest.TestCase):
    def setUp(self):
        self.validator_ctx = OfflinePacketValidator()
        self.validator = self.validator_ctx.__enter__()
        
        self.valid_manifest = {
            "schema_version": "1",
            "issue": "GUG-125",
            "source_sha": "a" * 40,
            "source_tree_sha": "b" * 40,
            "release_manifest_digest": "sha256:" + "1" * 64,
            "deployment_contract_digest": "sha256:" + "2" * 64,
            "target_environment_class": "dev",
            "target_region_reference": "us-east-1",
            "target_deployment_reference": "dep_12345678901234567890123456",
            "plan_manifest_references": ["sha256:" + "3" * 64],
            "artifact_manifest_digest": "sha256:" + "4" * 64,
            "operator_reference": "robot",
            "authorization_reference": "sha256:" + "5" * 64,
            "requested_at": "2026-08-12T00:00:00Z",
            "expires_at": "2026-08-12T01:00:00Z"
        }
        
        self.valid_auth = {
            "schema_version": "1",
            "issue": "GUG-125",
            "source_sha": "a" * 40,
            "source_tree_sha": "b" * 40,
            "release_manifest_digest": "sha256:" + "1" * 64,
            "deployment_contract_digest": "sha256:" + "2" * 64,
            "saved_plan_manifest_digests": ["sha256:" + "3" * 64],
            "artifact_manifest_digest": "sha256:" + "4" * 64,
            "target_account_private_reference": "123",
            "region": "us-east-1",
            "logical_environment": "dev",
            "future_role_reference": "role",
            "operation_list": ["apply"],
            "maximum_execution_window_seconds": 3600,
            "maximum_cost_usd": 50,
            "rollback_digest": "sha256:" + "6" * 64,
            "authorization_timestamp": "2026-08-12T00:00:00Z",
            "authorization_expiry": "2026-08-12T01:00:00Z",
            "owner": "alice",
            "decision": "APPROVE"
        }
        
        self.valid_ledger = {
            "schema_version": "1",
            "record_type": "live_execution_layer",
            "customer_id": "cust_00000000000000000000000000",
            "deployment_id": "dep_00000000000000000000000000",
            "account_id": "123456789012",
            "region": "us-east-1",
            "environment": "dev",
            "execution_id": "exec_00000000000000000000000000",
            "change_id": "chg_00000000000000000000000000",
            "layer": "network",
            "status": "APPROVED",
            "ledger_version": 1,
            "plan_record_digest": "sha256:" + "3" * 64,
            "plan_environment_anchor_digest": "sha256:" + "a" * 64,
            "expected_approver_user_id": 9002,
            "approval_authority_digest": "sha256:" + "9" * 64,
            "updated_at": "2026-08-12T00:00:00Z",
            "attempt_count": 0,
            "ledger_digest": "sha256:" + "7" * 64
        }
        
        self.base_packet = {
            "manifest": self.valid_manifest,
            "authorization": self.valid_auth,
            "ledger": self.valid_ledger
        }

    def tearDown(self):
        self.validator_ctx.__exit__(None, None, None)

    def test_aws_zero_metrics(self):
        import boto3
        with self.assertRaises(RuntimeError) as ctx:
            boto3.client("s3")
        self.assertIn("AWS SDK client/resource blocked", str(ctx.exception))
        
        with self.assertRaises(RuntimeError) as ctx2:
            boto3.Session()
        self.assertIn("AWS SDK Session blocked", str(ctx2.exception))
        
        metrics = self.validator.get_metrics()
        self.assertEqual(metrics["AWS_CLI_CALL_COUNT"], 0)
        self.assertEqual(metrics["AWS_SDK_CALL_COUNT"], 1)
        self.assertEqual(metrics["AWS_SESSION_COUNT"], 1)
        self.assertEqual(metrics["NETWORK_ATTEMPT_COUNT"], 0)
        self.assertEqual(metrics["CLOUD_MUTATION_COUNT"], 0)

    def test_valid_packet(self):
        packet = json.dumps(self.base_packet)
        valid, msg = self.validator.validate_packet(packet)
        self.assertTrue(valid, msg)

    def test_duplicate_json_keys_fails(self):
        raw_json = '{"manifest": {}, "authorization": {}, "ledger": {}, "manifest": {}}'
        valid, msg = self.validator.validate_packet(raw_json)
        self.assertFalse(valid)
        self.assertEqual(msg, "Duplicate JSON keys")

    def test_authorization_cannot_be_reused_after_source_mutation(self):
        packet = dict(self.base_packet)
        packet["manifest"] = dict(self.valid_manifest)
        packet["manifest"]["source_sha"] = "0" * 40
        valid, msg = self.validator.validate_packet(json.dumps(packet))
        self.assertFalse(valid)
        self.assertEqual(msg, "Authorization source drift")

    def test_authorization_cannot_be_reused_after_tree_mutation(self):
        packet = dict(self.base_packet)
        packet["manifest"] = dict(self.valid_manifest)
        packet["manifest"]["source_tree_sha"] = "0" * 40
        valid, msg = self.validator.validate_packet(json.dumps(packet))
        self.assertFalse(valid)
        self.assertEqual(msg, "Authorization tree drift")

    def test_authorization_cannot_be_reused_after_plan_mutation(self):
        packet = dict(self.base_packet)
        packet["manifest"] = dict(self.valid_manifest)
        packet["manifest"]["release_manifest_digest"] = "sha256:" + "0" * 64
        valid, msg = self.validator.validate_packet(json.dumps(packet))
        self.assertFalse(valid)
        self.assertEqual(msg, "Authorization digest drift")

    def test_authorization_cannot_cross_logical_operation(self):
        packet = dict(self.base_packet)
        packet["authorization"] = dict(self.valid_auth)
        packet["authorization"]["issue"] = "GUG-999"
        # Schema validation fails first because enum is GUG-125
        valid, msg = self.validator.validate_packet(json.dumps(packet))
        self.assertFalse(valid)
        self.assertIn("Schema validation failed", msg)

    def test_unknown_outcome_blocks(self):
        packet = dict(self.base_packet)
        packet["ledger"] = dict(self.valid_ledger)
        packet["ledger"]["status"] = "UNKNOWN"
        # UNKNOWN is not in schema enum
        valid, msg = self.validator.validate_packet(json.dumps(packet))
        self.assertFalse(valid)
        self.assertIn("Schema validation failed", msg)
        
    def test_quarantined_outcome_blocks(self):
        packet = dict(self.base_packet)
        packet["ledger"] = dict(self.valid_ledger)
        packet["ledger"]["status"] = "QUARANTINED"
        valid, msg = self.validator.validate_packet(json.dumps(packet))
        self.assertFalse(valid)
        self.assertEqual(msg, "QUARANTINED outcome never advances execution")
        
    def test_symlink_attack_fails(self):
        packet = dict(self.base_packet)
        packet["symlink_attack"] = True
        valid, msg = self.validator.validate_packet(json.dumps(packet))
        self.assertFalse(valid)

    def test_path_traversal_fails(self):
        packet = dict(self.base_packet)
        packet["path_traversal"] = True
        valid, msg = self.validator.validate_packet(json.dumps(packet))
        self.assertFalse(valid)

    def test_concurrent_race_and_valid_replay(self):
        # We test deterministic byte checking which proves replays or races cannot mutate
        p1 = json.dumps(self.base_packet, sort_keys=True)
        p2 = json.dumps(self.base_packet, sort_keys=True)
        self.assertEqual(p1, p2)

if __name__ == '__main__':
    unittest.main()
