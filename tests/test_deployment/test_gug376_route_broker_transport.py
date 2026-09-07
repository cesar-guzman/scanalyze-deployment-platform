from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

import pytest

from tooling import platform_authority_plan_permission_repair_route_broker as broker


@dataclass
class _Session:
    endpoint_url: str
    service_seen: str | None = None

    def client(self, service: str, **kwargs: Any) -> Any:
        assert kwargs == {"region_name": broker.REGION, "config": "sealed-config"}
        self.service_seen = service
        return SimpleNamespace(
            meta=SimpleNamespace(
                region_name=broker.REGION,
                endpoint_url=self.endpoint_url,
            )
        )


@pytest.mark.parametrize(
    ("service", "hostname"),
    sorted(broker._EXACT_SERVICE_ENDPOINT_HOSTS.items()),
)
def test_client_accepts_only_the_exact_regional_service_endpoint(
    service: str, hostname: str
) -> None:
    session = _Session(f"https://{hostname}")
    client = broker._client(session, service, "sealed-config")
    assert client.meta.endpoint_url == f"https://{hostname}"
    assert session.service_seen == service


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://sts.us-east-1.amazonaws.com",
        "https://sts.us-east-1.amazonaws.com:443",
        "https://sts.us-east-1.amazonaws.com/not-root",
        "https://sts.us-east-1.amazonaws.com?redirect=1",
        "https://sts.us-east-1.amazonaws.com#fragment",
        "https://attacker.amazonaws.com",
        "https://sts.us-west-2.amazonaws.com",
        "https://user@sts.us-east-1.amazonaws.com",
    ],
)
def test_client_rejects_every_endpoint_drift(endpoint: str) -> None:
    with pytest.raises(broker.RouteBrokerError) as caught:
        broker._client(_Session(endpoint), "sts", "sealed-config")
    assert caught.value.code == "AWS_CLIENT_ENDPOINT_INVALID"


def test_client_rejects_unknown_service_before_session_use() -> None:
    session = _Session("https://example.invalid")
    with pytest.raises(broker.RouteBrokerError) as caught:
        broker._client(session, "ec2", "sealed-config")
    assert caught.value.code == "AWS_CLIENT_SERVICE_INVALID"
    assert session.service_seen is None


def test_change_set_parameter_readback_accepts_only_exact_value_or_previous() -> None:
    request = [
        {"ParameterKey": "Changed", "ParameterValue": "false"},
        {"ParameterKey": "Private", "UsePreviousValue": True},
    ]
    observed = [
        {"ParameterKey": "Changed", "ParameterValue": "false"},
        {"ParameterKey": "Private", "UsePreviousValue": True},
    ]
    assert broker._change_set_parameters_match(observed, request)
    assert not broker._change_set_parameters_match(
        [
            observed[0],
            {
                "ParameterKey": "Private",
                "ParameterValue": "****",
                "UsePreviousValue": True,
            },
        ],
        request,
    )
    assert not broker._change_set_parameters_match(
        [{**observed[0], "ParameterValue": "true"}, observed[1]], request
    )
    normalized = [
        observed[0],
        {"ParameterKey": "Private", "ParameterValue": "private-value"},
    ]
    assert broker._change_set_parameters_match(
        normalized,
        request,
        expected_terminal_parameters_digest=broker.digest_value(
            {"Changed": "false", "Private": "private-value"}
        ),
    )
