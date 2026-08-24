from __future__ import annotations
import json, subprocess, sys; from pathlib import Path
from jsonschema import Draft202012Validator; from tooling.platform_authority_gug376_identity_center_inventory_collector import validate_public_receipt
ROOT = Path(__file__).parents[2]
SCRIPT = ROOT / "scripts/deployment/platform-authority-gug376-identity-center-inventory.py"
def test_cli_is_isolated_inert_and_has_no_provider_imports() -> None:
    result = subprocess.run([sys.executable, "-I", "-S", SCRIPT, "capture"], text=True, capture_output=True, check=False)
    assert result.returncode == 2 and "STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED" in result.stderr and "Traceback" not in result.stderr
    source = (ROOT / "tooling/platform_authority_gug376_identity_center_inventory_collector.py").read_text()
    assert all(token not in source for token in ("boto3", "botocore", "requests.", "urllib.", "socket.", "execute(", "ListUsers", "GetUserId", "list_users", "get_user_id"))
def test_identity_center_public_receipt_schema_accepts_safe_and_rejects_leak() -> None:
    schema = json.loads((ROOT / "schemas/platform-authority-gug376-identity-center-inventory-receipt.v1.schema.json").read_text())
    valid = json.loads((ROOT / "fixtures/valid/platform-authority-gug376-identity-center-inventory-receipt-v1-synthetic.json").read_text())
    invalid = json.loads((ROOT / "fixtures/invalid/platform-authority-gug376-identity-center-inventory-receipt-v1-sensitive-leak.json").read_text())
    validator = Draft202012Validator(schema); terminal = dict(valid, classification="EXACT_PRESENT_NO_TOUCH", stable=False); mismatch = dict(valid, snapshot_count=2); validate_public_receipt(valid); assert not list(validator.iter_errors(valid)) and list(validator.iter_errors(invalid)) and list(validator.iter_errors(terminal)) and list(validator.iter_errors(mismatch))
