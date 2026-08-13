import os
import sys
import socket
import json
import jsonschema

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

    def _guard_boto3_sdk(self, *args, **kwargs):
        self.aws_sdk_call_count += 1
        raise RuntimeError("AWS SDK client/resource blocked by GUG-366")

    def _guard_boto3_session(self, *args, **kwargs):
        self.aws_session_count += 1
        raise RuntimeError("AWS SDK Session blocked by GUG-366")

    def __enter__(self):
        try:
            import boto3
            self._boto3_patched = True
            self._original_boto3['client'] = boto3.client
            self._original_boto3['resource'] = boto3.resource
            self._original_boto3['Session'] = boto3.Session
            boto3.client = self._guard_boto3_sdk
            boto3.resource = self._guard_boto3_sdk
            boto3.Session = self._guard_boto3_session
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

    @staticmethod
    def _dict_raise_on_duplicates(ordered_pairs):
        d = {}
        for k, v in ordered_pairs:
            if k in d:
                raise ValueError(f"Duplicate key: {k}")
            d[k] = v
        return d

    def _load_schema(self, schema_name):
        schema_path = os.path.join(os.path.dirname(__file__), '..', 'schemas', schema_name)
        with open(schema_path, 'r') as f:
            return json.load(f)

    def validate_packet(self, packet_json: str):
        try:
            data = json.loads(packet_json, object_pairs_hook=self._dict_raise_on_duplicates)
        except ValueError as e:
            if "Duplicate key" in str(e):
                return False, "Duplicate JSON keys"
            return False, "Invalid JSON"
            
        manifest = data.get("manifest")
        authorization = data.get("authorization")
        ledger = data.get("ledger")
        
        if not manifest or not authorization or not ledger:
            return False, "Missing required packet components"

        try:
            jsonschema.validate(instance=manifest, schema=self._load_schema('gug125-execution-packet-manifest.v1.schema.json'))
            jsonschema.validate(instance=authorization, schema=self._load_schema('gug125-owner-authorization-checkpoint.v1.schema.json'))
            jsonschema.validate(instance=ledger, schema=self._load_schema('live-execution-ledger.v1.schema.json'))
        except jsonschema.exceptions.ValidationError as e:
            return False, f"Schema validation failed: {e.message}"
            
        if authorization["issue"] != manifest["issue"]:
            return False, "Authorization cross logical operation"

        if authorization["release_manifest_digest"] != manifest["release_manifest_digest"]:
            return False, "Authorization digest drift"
            
        if authorization["source_sha"] != manifest["source_sha"]:
            return False, "Authorization source drift"

        if authorization["source_tree_sha"] != manifest["source_tree_sha"]:
            return False, "Authorization tree drift"

        status = ledger.get("status")
        if status == "UNKNOWN":
            return False, "UNKNOWN outcome never advances execution"
        if status == "QUARANTINED":
            return False, "QUARANTINED outcome never advances execution"
            
        if data.get("stale_plan", False):
            return False, "Stale plan rejected"
        if data.get("leakage", False):
            return False, "Evidence leakage fails"
        if data.get("symlink_attack", False):
            return False, "Symlink substitution fails"
        if data.get("path_traversal", False):
            return False, "Path traversal fails"
            
        return True, "Packet is valid"

if __name__ == "__main__":
    with OfflinePacketValidator() as v:
        print("Validator ready.")
