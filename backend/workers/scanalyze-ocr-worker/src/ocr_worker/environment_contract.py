import re

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

_CUSTOMER_ID_PATTERN = re.compile(r"cust_[0-9A-HJKMNP-TV-Z]{26}")
_DEPLOYMENT_ID_PATTERN = re.compile(r"dep_[0-9A-HJKMNP-TV-Z]{26}")


def require_runtime_environment(value: str | None) -> str:
    if not isinstance(value, str):
        raise RuntimeError("SCANALYZE_ENV is required")
    if value not in SUPPORTED_RUNTIME_ENVIRONMENTS:
        raise RuntimeError("SCANALYZE_ENV is unsupported")
    return value


def project_log_environment(value: object) -> str:
    if isinstance(value, str) and value in SUPPORTED_RUNTIME_ENVIRONMENTS:
        return value
    return "unknown"


def require_customer_id(value: str | None) -> str:
    if not isinstance(value, str):
        raise RuntimeError("SCANALYZE_DEPLOYMENT_CUSTOMER_ID is required")
    if not _CUSTOMER_ID_PATTERN.fullmatch(value):
        raise RuntimeError(f"Invalid SCANALYZE_DEPLOYMENT_CUSTOMER_ID format")
    return value


def require_deployment_id(value: str | None) -> str:
    if not isinstance(value, str):
        raise RuntimeError("SCANALYZE_DEPLOYMENT_ID is required")
    if not _DEPLOYMENT_ID_PATTERN.fullmatch(value):
        raise RuntimeError(f"Invalid SCANALYZE_DEPLOYMENT_ID format")
    return value


def project_customer_id(value: object) -> str:
    if isinstance(value, str) and _CUSTOMER_ID_PATTERN.fullmatch(value):
        return value
    return "unknown"


def project_deployment_id(value: object) -> str:
    if isinstance(value, str) and _DEPLOYMENT_ID_PATTERN.fullmatch(value):
        return value
    return "unknown"
