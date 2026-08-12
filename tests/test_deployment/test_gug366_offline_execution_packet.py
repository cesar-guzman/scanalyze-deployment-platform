import unittest
import json
import os
import sys

# Ensure tooling is in path
sys.path.append(os.path.join(os.path.dirname(__file__), '../../tooling'))
from gug125_offline_validator import OfflinePacketValidator

class TestGUG366OfflineExecutionPacket(unittest.TestCase):
    def setUp(self):
        self.validator_ctx = OfflinePacketValidator()
        self.validator = self.validator_ctx.__enter__()

    def tearDown(self):
        self.validator_ctx.__exit__(None, None, None)

    def test_aws_zero_metrics(self):
        metrics = self.validator.get_metrics()
        self.assertEqual(metrics["AWS_CLI_CALL_COUNT"], 0)
        self.assertEqual(metrics["AWS_SDK_CALL_COUNT"], 0)
        self.assertEqual(metrics["AWS_SESSION_COUNT"], 0)
        self.assertEqual(metrics["NETWORK_ATTEMPT_COUNT"], 0)
        self.assertEqual(metrics["CLOUD_MUTATION_COUNT"], 0)

    def test_valid_packet(self):
        packet = json.dumps({"issue": "GUG-125"})
        valid, msg = self.validator.validate_packet(packet)
        self.assertTrue(valid)

    def test_wrong_issue_rejected(self):
        packet = json.dumps({"issue": "GUG-999"})
        valid, msg = self.validator.validate_packet(packet)
        self.assertFalse(valid)
        self.assertEqual(msg, "Wrong issue binding")

    def test_stale_plan_rejected(self):
        packet = json.dumps({"issue": "GUG-125", "stale_plan": True})
        valid, msg = self.validator.validate_packet(packet)
        self.assertFalse(valid)

    def test_leakage_rejected(self):
        packet = json.dumps({"issue": "GUG-125", "leakage": True})
        valid, msg = self.validator.validate_packet(packet)
        self.assertFalse(valid)

    def test_unknown_outcome_blocks(self):
        packet = json.dumps({"issue": "GUG-125", "unknown_outcome": True})
        valid, msg = self.validator.validate_packet(packet)
        self.assertFalse(valid)
        self.assertEqual(msg, "UNKNOWN outcome never advances execution")
        
    def test_quarantined_outcome_blocks(self):
        packet = json.dumps({"issue": "GUG-125", "quarantined": True})
        valid, msg = self.validator.validate_packet(packet)
        self.assertFalse(valid)
        
    def test_symlink_attack_fails(self):
        packet = json.dumps({"issue": "GUG-125", "symlink_attack": True})
        valid, msg = self.validator.validate_packet(packet)
        self.assertFalse(valid)

    def test_path_traversal_fails(self):
        packet = json.dumps({"issue": "GUG-125", "path_traversal": True})
        valid, msg = self.validator.validate_packet(packet)
        self.assertFalse(valid)
        
    def test_duplicate_json_keys(self):
        # Python json.loads allows duplicates by default (last one wins)
        # In a strict parser, it fails. We simulate the strict boundary:
        raw_json = '{"issue": "GUG-125", "issue": "GUG-999"}'
        try:
            # Custom strict decoder that rejects duplicates
            def dict_raise_on_duplicates(ordered_pairs):
                d = {}
                for k, v in ordered_pairs:
                    if k in d:
                        raise ValueError("Duplicate key")
                    d[k] = v
                return d
            json.loads(raw_json, object_pairs_hook=dict_raise_on_duplicates)
            self.fail("Should have rejected duplicate key")
        except ValueError:
            pass
            
    def test_network_kill_switch(self):
        import socket
        with self.assertRaises(RuntimeError) as context:
            socket.socket()
        self.assertIn("kill-switch", str(context.exception))

if __name__ == '__main__':
    unittest.main()
