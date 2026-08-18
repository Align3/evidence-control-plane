"""Pure contract tests; live Salesforce behaviour is covered separately."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from services.connectors import (
    AttributionSurface,
    ConfirmationAccessPath,
    EnumerationWindow,
    SalesforceAccessToken,
    SalesforceApiError,
    SalesforceConnector,
    SalesforceConnectorConfig,
    SalesforceRestClient,
)
from services.connectors.salesforce import _case_enumeration_soql

USER_ID = "005000000000001AAA"
WINDOW = EnumerationWindow(
    datetime(2026, 8, 18, 10, tzinfo=UTC),
    datetime(2026, 8, 18, 11, tzinfo=UTC),
)


def _client() -> SalesforceRestClient:
    return SalesforceRestClient(
        SalesforceAccessToken(
            access_token="not-used-by-pure-tests",  # noqa: S106 -- inert fixture value
            instance_url="https://example.my.salesforce.com",
            identity_url="https://login.salesforce.com/id/org/user",
            token_type="Bearer",  # noqa: S106 -- OAuth type, not a password
        ),
        api_version="v66.0",
    )


def test_capabilities_report_shared_confirmation_and_conditional_attribution() -> None:
    connector = SalesforceConnector(
        client=_client(),
        config=SalesforceConnectorConfig(
            api_version="v66.0", integration_user_id=USER_ID
        ),
    )

    capabilities = connector.capabilities()
    assert capabilities.enumeration
    assert capabilities.confirmation
    assert capabilities.authoritative_time
    assert capabilities.settlement_lag == timedelta(0)
    assert capabilities.attribution_surface is AttributionSurface.CALLER_SETTABLE_FIELD
    assert (
        capabilities.confirmation_access
        is ConfirmationAccessPath.SHARED_WITH_ENUMERATION
    )


def test_case_query_combines_population_window_and_identity_filter() -> None:
    soql = _case_enumeration_soql(integration_user_id=USER_ID, window=WINDOW)

    assert "FROM Case" in soql
    assert f"CreatedById = '{USER_ID}'" in soql
    assert "CreatedDate >= 2026-08-18T10:00:00.000Z" in soql
    assert "CreatedDate < 2026-08-18T11:00:00.000Z" in soql
    assert soql.endswith("ORDER BY CreatedDate ASC, Id ASC")
    assert soql.count("WHERE") == 1


def test_salesforce_ids_are_closed_before_soql_interpolation() -> None:
    with pytest.raises(ValueError, match="Salesforce ID"):
        SalesforceConnectorConfig(
            api_version="v66.0",
            integration_user_id="005' OR CreatedById != ''",
        )


def test_next_records_url_cannot_escape_the_configured_query_api() -> None:
    client = _client()

    with pytest.raises(SalesforceApiError, match="invalid nextRecordsUrl"):
        client.next_query_page("https://attacker.example/steal")
