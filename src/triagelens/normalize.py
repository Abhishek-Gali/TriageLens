"""Deterministic alert normalization (P1-02)."""

from __future__ import annotations

from typing import Any

from triagelens.contracts import (
    ALLOWED_ENTITY_KEYS,
    ALLOWED_METADATA_KEYS,
    KNOWN_PROFILES,
    CanonicalAlert,
    NormalizedAlert,
    parse_and_validate_timestamp,
)


def normalize_alert(alert: CanonicalAlert) -> NormalizedAlert:
    """Perform pure, deterministic representation normalization without inventing evidence."""
    dt_utc = parse_and_validate_timestamp(alert.observed_at)
    if dt_utc is None:
        raise ValueError("CanonicalAlert must have a validated timestamp")

    if dt_utc.microsecond:
        observed_at_utc = dt_utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    else:
        observed_at_utc = dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

    profile_key = (alert.family, alert.event_name)
    normalized_obs: dict[str, Any] = {}
    if profile_key in KNOWN_PROFILES:
        # Ensure all essential profile keys exist in the dictionary with None for missing fields,
        # never coercing None to 0 or False (INV-05, RULE_CATALOGUE.md).
        for key in sorted(KNOWN_PROFILES[profile_key]):
            normalized_obs[key] = alert.observations.get(key, None)
    else:
        for key in sorted(alert.observations.keys()):
            normalized_obs[key] = alert.observations[key]

    normalized_entities: dict[str, str | None] = {}
    for key in sorted(ALLOWED_ENTITY_KEYS):
        if key in alert.entities and alert.entities[key] is not None:
            normalized_entities[key] = alert.entities[key]

    normalized_metadata: dict[str, str | None] = {}
    for key in sorted(ALLOWED_METADATA_KEYS):
        if key in alert.metadata and alert.metadata[key] is not None:
            normalized_metadata[key] = alert.metadata[key]

    return NormalizedAlert(
        schema_version=alert.schema_version,
        alert_id=alert.alert_id,
        observed_at_utc=observed_at_utc,
        raw_observed_at=alert.observed_at,
        family=alert.family,
        source=alert.source,
        event_name=alert.event_name,
        observations=normalized_obs,
        source_severity=alert.source_severity,
        entities=normalized_entities,
        source_text=alert.source_text,
        metadata=normalized_metadata,
    )
