SUPPORTED_ROUTES = frozenset({"bank", "personal", "gov"})


def route_is_allowed(config_tenant: str, message_route: str) -> bool:
    """Allow domain routes through platform config, or an exact domain binding."""
    if message_route not in SUPPORTED_ROUTES:
        return False
    return config_tenant == "platform" or config_tenant == message_route


def structured_key_for(
    customer_id: str,
    deployment_id: str,
    message_route: str,
    document_id: str,
) -> str:
    return (
        f"customers/{customer_id}/deployments/{deployment_id}/"
        f"documents/{document_id}/structured/{message_route}/result.json"
    )
