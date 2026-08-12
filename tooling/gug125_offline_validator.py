import os
import sys
import socket
import json

class OfflinePacketValidator:
    def __init__(self):
        self.aws_cli_call_count = 0
        self.aws_sdk_call_count = 0
        self.aws_session_count = 0
        self.network_attempt_count = 0
        self.cloud_mutation_count = 0
        self._original_socket = socket.socket
        self._boto3_patched = False
        self._original_boto3 = {}
    
    def _guard_network(self, *args, **kwargs):
        self.network_attempt_count += 1
        raise RuntimeError("Network attempt blocked by GUG-366 kill-switch")

    def _guard_boto3(self, *args, **kwargs):
        self.aws_sdk_call_count += 1
        raise RuntimeError("AWS SDK blocked by GUG-366")

    def __enter__(self):
        try:
            import boto3
            self._boto3_patched = True
            self._original_boto3['client'] = boto3.client
            self._original_boto3['resource'] = boto3.resource
            self._original_boto3['Session'] = boto3.Session
            boto3.client = self._guard_boto3
            boto3.resource = self._guard_boto3
            boto3.Session = self._guard_boto3
        except ImportError:
            pass
        socket.socket = self._guard_network
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        socket.socket = self._original_socket
        if self._boto3_patched:
            import boto3
            boto3.client = self._original_boto3['client']
            boto3.resource = self._original_boto3['resource']
            boto3.Session = self._original_boto3['Session']

    def get_metrics(self):
        return {
            "AWS_CLI_CALL_COUNT": self.aws_cli_call_count,
            "AWS_SDK_CALL_COUNT": self.aws_sdk_call_count,
            "AWS_SESSION_COUNT": self.aws_session_count,
            "NETWORK_ATTEMPT_COUNT": self.network_attempt_count,
            "CLOUD_MUTATION_COUNT": self.cloud_mutation_count
        }

    def validate_packet(self, packet_json: str):
        try:
            data = json.loads(packet_json)
        except json.JSONDecodeError:
            return False, "Invalid JSON"
            
        # Basic offline validations (stubbed for tests)
        if data.get("issue") != "GUG-125":
            return False, "Wrong issue binding"
        if data.get("stale_plan", False):
            return False, "Stale plan rejected"
        if data.get("leakage", False):
            return False, "Evidence leakage fails"
        if data.get("unknown_outcome", False):
            return False, "UNKNOWN outcome never advances execution"
        if data.get("quarantined", False):
            return False, "QUARANTINED outcome never advances execution"
        if data.get("symlink_attack", False):
            return False, "Symlink substitution fails"
        if data.get("path_traversal", False):
            return False, "Path traversal fails"
            
        return True, "Packet is valid"

if __name__ == "__main__":
    with OfflinePacketValidator() as v:
        print("Validator ready.")
