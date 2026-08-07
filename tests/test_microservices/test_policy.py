import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(repo_root))

from tooling.check_microservices import check_source_text, add_error


def test_canonical_environment_contract_passes():
    text = '''
SUPPORTED_RUNTIME_ENVIRONMENTS = {
    "local",
    "test",
    "ci",
    "demo",
    "sandbox",
    "dev",
    "staging",
    "production"
}
    '''
    errors = check_source_text(Path("environment_contract.py"), True, text)
    assert not any("deployment/customer label must be injected" in e for e in errors)


def test_production_default_fails():
    text = 'os.getenv("SCANALYZE_ENV", "demo")'
    errors = check_source_text(Path("some_file.py"), True, text)
    assert any("deployment identity must not have a nonempty default" in e for e in errors)


def test_hardcoded_bcm_corp_fails():
    text = 'label = "bcm-corp"'
    errors = check_source_text(Path("some_file.py"), True, text)
    assert any("client-specific identifier" in e for e in errors)


def test_account_specific_ecr_fails():
    text = 'image = "123456789012.dkr.ecr.us-east-1.amazonaws.com/image"'
    errors = check_source_text(Path("some_file.py"), True, text)
    assert any("account-specific ECR URI" in e for e in errors)


def test_hardcoded_demo_outside_contract_fails():
    text = 'label = "demo"'
    errors = check_source_text(Path("some_file.py"), True, text)
    assert any("deployment/customer label must be injected" in e for e in errors)

def test_source_obfuscation_is_not_needed():
    # We should ensure that we do not need to obfuscate strings.
    # The literal "demo" inside environment_contract.py is allowed.
    text = 'valid = "demo"'
    errors = check_source_text(Path("environment_contract.py"), True, "SUPPORTED_RUNTIME_ENVIRONMENTS\n" + text)
    assert not any("deployment/customer label must be injected" in e for e in errors)
