"""Read-only EV-42 tests against the qualified Salesforce Developer org.

No Salesforce response is mocked. The suite is opt-in so ordinary CI does not
depend on a customer system or credentials. Secrets and tokens are never
printed or stored as fixtures on disk.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from services.connectors import (
    ActionReference,
    ConnectorScope,
    EnumerationWindow,
    FileRs256Signer,
    SalesforceConnector,
    SalesforceConnectorConfig,
    SalesforceJwtBearerAuth,
    SalesforceJwtBearerConfig,
    SalesforceRestClient,
    confirm_salesforce_identity,
    exchange_jwt_bearer,
)

pytestmark = pytest.mark.integration


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        pytest.skip(f"{name} is required for live Salesforce tests")
    return value


@pytest.fixture(scope="module")
def live_connector() -> tuple[SalesforceConnector, SalesforceConnectorConfig]:
    client_id = _required_env("SALESFORCE_CLIENT_ID")
    username = _required_env("SALESFORCE_USERNAME")
    token_endpoint = _required_env("SALESFORCE_TOKEN_ENDPOINT")
    key_path = Path(_required_env("SALESFORCE_PRIVATE_KEY_PATH"))
    auth_config = SalesforceJwtBearerConfig.from_token_endpoint(
        client_id=client_id,
        subject=username,
        token_endpoint=token_endpoint,
    )
    token = exchange_jwt_bearer(
        SalesforceJwtBearerAuth(
            config=auth_config,
            signer=FileRs256Signer(key_path),
        ).build_token_request()
    )
    identity = confirm_salesforce_identity(token, expected_username=username)
    connector_config = SalesforceConnectorConfig(
        api_version="v67.0",
        integration_user_id=identity.user_id,
    )
    client = SalesforceRestClient(
        token,
        api_version=connector_config.api_version,
        query_batch_size=connector_config.query_batch_size,
    )
    return SalesforceConnector(client=client, config=connector_config), connector_config


def test_live_token_is_bound_to_the_integration_user(
    live_connector: tuple[SalesforceConnector, SalesforceConnectorConfig],
) -> None:
    _connector, config = live_connector
    assert config.integration_user_id
    assert _required_env("SALESFORCE_USERNAME") == "agent@probe.local"


def test_live_permission_state_is_clean_for_conditional_c1(
    live_connector: tuple[SalesforceConnector, SalesforceConnectorConfig],
) -> None:
    connector, _config = live_connector

    result = connector.revalidate_qualification()

    assert result.outcome.value == "confirmed-clean"
    assert result.c1_eligible


def test_live_case_enumeration_and_confirmation(
    live_connector: tuple[SalesforceConnector, SalesforceConnectorConfig],
) -> None:
    connector, config = live_connector
    scope = ConnectorScope(
        config.action_family,
        config.destination_system,
        config.scope_parameters,
    )
    window = EnumerationWindow(
        datetime(2026, 8, 18, tzinfo=UTC),
        datetime(2026, 8, 19, tzinfo=UTC),
    )

    population = connector.enumerate(scope, window)

    assert population.body.pagination_complete
    assert not population.body.result_cap_hit
    assert population.body.count == len(population.body.record_identifiers or ())
    assert (population.body.model_extra or {})["qualification_condition"] == (
        "confirmed-clean"
    )
    identifiers = population.body.record_identifiers or []
    assert identifiers, "the committed qualification records known Case data on 2026-08-18"
    confirmation = connector.confirm(
        ActionReference(
            action_id="ev42-live-read-only-confirmation",
            destination_record_id=identifiers[0],
        )
    )
    assert confirmation.body.reconciliation_status == "matched"
    assert confirmation.body.destination_record_id == identifiers[0]
