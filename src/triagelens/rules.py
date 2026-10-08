"""Deterministic rule catalogue (demo-v1) and rule evaluation engine (P2-01, P2-02)."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Callable

from triagelens.config import RULESET_ID, RULESET_REVIEW_STATUS
from triagelens.contracts import NormalizedAlert, RuleEvaluationRecord


@dataclass(frozen=True)
class RuleDefinition:
    """Declarative metadata and trusted predicate for a single triage rule."""

    rule_id: str
    ruleset_id: str
    review_status: str
    family: str
    event_name: str
    category: str  # suspicious | benign_candidate
    required_fields: tuple[str, ...]
    evidence_paths: tuple[str, ...]
    description: str
    predicate_spec: str
    predicate: Callable[[dict[str, Any]], bool]


def _is_missing_observation(field_name: str, val: Any) -> bool:
    """Check whether an observation value is missing/unknown for predicate evaluation."""
    if val is None:
        return True
    if field_name in ("signature_status", "location_category") and val == "unknown":
        return True
    return False


DEMO_V1_RULES: tuple[RuleDefinition, ...] = (
    RuleDefinition(
        rule_id="AUTH-S01",
        ruleset_id=RULESET_ID,
        review_status=RULESET_REVIEW_STATUS,
        family="authentication",
        event_name="login_sequence",
        category="suspicious",
        required_fields=("failed_attempts", "window_seconds", "success_after_failures"),
        evidence_paths=(
            "observations.failed_attempts",
            "observations.window_seconds",
            "observations.success_after_failures",
        ),
        description="High-rate authentication failures followed by login success within 300 seconds",
        predicate_spec="failed_attempts >= 10 AND window_seconds <= 300 AND success_after_failures == true",
        predicate=lambda obs: (
            obs["failed_attempts"] >= 10
            and obs["window_seconds"] <= 300
            and obs["success_after_failures"] is True
        ),
    ),
    RuleDefinition(
        rule_id="AUTH-B01",
        ruleset_id=RULESET_ID,
        review_status=RULESET_REVIEW_STATUS,
        family="authentication",
        event_name="login_sequence",
        category="benign_candidate",
        required_fields=("failed_attempts", "success_after_failures", "approved_origin"),
        evidence_paths=(
            "observations.failed_attempts",
            "observations.success_after_failures",
            "observations.approved_origin",
        ),
        description="At most 2 failed attempts followed by login success from an approved origin",
        predicate_spec="failed_attempts <= 2 AND success_after_failures == true AND approved_origin == true",
        predicate=lambda obs: (
            obs["failed_attempts"] <= 2
            and obs["success_after_failures"] is True
            and obs["approved_origin"] is True
        ),
    ),
    RuleDefinition(
        rule_id="PROC-S01",
        ruleset_id=RULESET_ID,
        review_status=RULESET_REVIEW_STATUS,
        family="process",
        event_name="process_start",
        category="suspicious",
        required_fields=("signature_status", "location_category"),
        evidence_paths=(
            "observations.signature_status",
            "observations.location_category",
        ),
        description="Unsigned executable started from a user-writable location",
        predicate_spec="signature_status == 'unsigned' AND location_category == 'user_writable'",
        predicate=lambda obs: (
            obs["signature_status"] == "unsigned"
            and obs["location_category"] == "user_writable"
        ),
    ),
    RuleDefinition(
        rule_id="PROC-B01",
        ruleset_id=RULESET_ID,
        review_status=RULESET_REVIEW_STATUS,
        family="process",
        event_name="process_start",
        category="benign_candidate",
        required_fields=("signature_status", "location_category", "approved_executable"),
        evidence_paths=(
            "observations.signature_status",
            "observations.location_category",
            "observations.approved_executable",
        ),
        description="Signed and approved executable started from a managed location",
        predicate_spec=(
            "signature_status == 'signed' AND location_category == 'managed' "
            "AND approved_executable == true"
        ),
        predicate=lambda obs: (
            obs["signature_status"] == "signed"
            and obs["location_category"] == "managed"
            and obs["approved_executable"] is True
        ),
    ),
    RuleDefinition(
        rule_id="NET-S01",
        ruleset_id=RULESET_ID,
        review_status=RULESET_REVIEW_STATUS,
        family="network",
        event_name="connection_summary",
        category="suspicious",
        required_fields=("destination_blocklisted", "connection_count"),
        evidence_paths=(
            "observations.destination_blocklisted",
            "observations.connection_count",
        ),
        description="One or more network connections to a blocklisted destination",
        predicate_spec="destination_blocklisted == true AND connection_count >= 1",
        predicate=lambda obs: (
            obs["destination_blocklisted"] is True
            and obs["connection_count"] >= 1
        ),
    ),
    RuleDefinition(
        rule_id="NET-B01",
        ruleset_id=RULESET_ID,
        review_status=RULESET_REVIEW_STATUS,
        family="network",
        event_name="connection_summary",
        category="benign_candidate",
        required_fields=("approved_destination", "destination_blocklisted", "connection_count"),
        evidence_paths=(
            "observations.approved_destination",
            "observations.destination_blocklisted",
            "observations.connection_count",
        ),
        description="One or more network connections to an approved, non-blocklisted destination",
        predicate_spec=(
            "approved_destination == true AND destination_blocklisted == false "
            "AND connection_count >= 1"
        ),
        predicate=lambda obs: (
            obs["approved_destination"] is True
            and obs["destination_blocklisted"] is False
            and obs["connection_count"] >= 1
        ),
    ),
)


def get_ruleset_sha256(ruleset_id: str = RULESET_ID) -> str:
    """Compute a deterministic SHA-256 digest of the active ruleset definitions."""
    if ruleset_id != RULESET_ID:
        raise ValueError(f"Unsupported ruleset_id: {ruleset_id!r}")
    serializable = [
        {
            "rule_id": r.rule_id,
            "ruleset_id": r.ruleset_id,
            "review_status": r.review_status,
            "family": r.family,
            "event_name": r.event_name,
            "category": r.category,
            "required_fields": list(r.required_fields),
            "evidence_paths": list(r.evidence_paths),
            "predicate_spec": r.predicate_spec,
        }
        for r in DEMO_V1_RULES
    ]
    payload = json.dumps(serializable, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def evaluate_rules(alert: NormalizedAlert, ruleset_id: str = RULESET_ID) -> tuple[RuleEvaluationRecord, ...]:
    """Evaluate all rules in the ruleset using the 4 states in RULE_CATALOGUE.md."""
    if ruleset_id != RULESET_ID:
        raise ValueError(f"Unsupported ruleset_id: {ruleset_id!r}")

    records: list[RuleEvaluationRecord] = []
    for rule in DEMO_V1_RULES:
        if alert.family != rule.family or alert.event_name != rule.event_name:
            records.append(
                RuleEvaluationRecord(
                    rule_id=rule.rule_id,
                    state="not_applicable",
                    category=rule.category,
                    evidence_paths=(),
                    missing_fields=(),
                    description=rule.description,
                )
            )
            continue

        missing_paths: list[str] = []
        for field_name in rule.required_fields:
            val = alert.observations.get(field_name)
            if _is_missing_observation(field_name, val):
                missing_paths.append(f"observations.{field_name}")

        if missing_paths:
            records.append(
                RuleEvaluationRecord(
                    rule_id=rule.rule_id,
                    state="not_evaluable",
                    category=rule.category,
                    evidence_paths=(),
                    missing_fields=tuple(missing_paths),
                    description=rule.description,
                )
            )
            continue

        matched = rule.predicate(alert.observations)
        records.append(
            RuleEvaluationRecord(
                rule_id=rule.rule_id,
                state="matched" if matched else "not_matched",
                category=rule.category,
                evidence_paths=rule.evidence_paths if matched else (),
                missing_fields=(),
                description=rule.description,
            )
        )

    return tuple(records)
