"""Deterministic decision policy and advisory ML escalation (P2-02, P5-04)."""

from __future__ import annotations

from triagelens.config import POLICY_VERSION
from triagelens.contracts import (
    KNOWN_PROFILES,
    ClassifierOutput,
    DecisionRecord,
    NormalizedAlert,
    RuleEvaluationRecord,
)

PROFILE_ESSENTIAL_ORDER: dict[tuple[str, str], tuple[str, ...]] = {
    ("authentication", "login_sequence"): (
        "failed_attempts",
        "window_seconds",
        "success_after_failures",
        "approved_origin",
    ),
    ("process", "process_start"): (
        "signature_status",
        "location_category",
        "approved_executable",
    ),
    ("network", "connection_summary"): (
        "connection_count",
        "window_seconds",
        "destination_blocklisted",
        "approved_destination",
    ),
}


def _dedupe_preserve_order(items: list[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return tuple(ordered)


def check_profile_completeness(alert: NormalizedAlert) -> tuple[str, ...]:
    """Return canonical paths of any missing or unknown essential profile observations."""
    profile_key = (alert.family, alert.event_name)
    essential_fields = PROFILE_ESSENTIAL_ORDER.get(profile_key, ())
    missing: list[str] = []
    for field_name in essential_fields:
        val = alert.observations.get(field_name)
        if val is None:
            missing.append(f"observations.{field_name}")
        elif field_name in ("signature_status", "location_category") and val == "unknown":
            # RULE_CATALOGUE.md: Signature unknown and location unknown produce missing_evidence
            missing.append(f"observations.{field_name}")
    return tuple(missing)


def check_contradictions_and_conflicts(
    alert: NormalizedAlert,
) -> tuple[list[str], list[str]]:
    """Check for contradictory_evidence and policy_conflict per RULE_CATALOGUE.md step 3."""
    reasons: list[str] = []
    conflict_paths: list[str] = []
    profile_key = (alert.family, alert.event_name)

    if profile_key == ("network", "connection_summary"):
        if (
            alert.observations.get("destination_blocklisted") is True
            and alert.observations.get("approved_destination") is True
        ):
            reasons.append("contradictory_evidence")
            conflict_paths.extend(
                [
                    "observations.destination_blocklisted",
                    "observations.approved_destination",
                ]
            )

    elif profile_key == ("process", "process_start"):
        if (
            alert.observations.get("signature_status") == "unsigned"
            and alert.observations.get("approved_executable") is True
        ):
            reasons.append("policy_conflict")
            conflict_paths.extend(
                [
                    "observations.signature_status",
                    "observations.approved_executable",
                ]
            )

    return reasons, conflict_paths


def apply_decision_policy(
    alert: NormalizedAlert,
    rule_evaluations: tuple[RuleEvaluationRecord, ...],
    classifier_output: ClassifierOutput | None = None,
) -> DecisionRecord:
    """Apply the 7-step deterministic decision policy defined in RULE_CATALOGUE.md."""
    profile_key = (alert.family, alert.event_name)

    # Step 2: Recognized family with unknown event profile -> needs_review with unsupported_pattern
    if profile_key not in KNOWN_PROFILES:
        return DecisionRecord(
            baseline_disposition="needs_review",
            disposition="needs_review",
            review_reasons=("unsupported_pattern",),
            matched_rule_ids=(),
            evidence_paths=("family", "event_name"),
            rule_evaluations=rule_evaluations,
            policy_version=POLICY_VERSION,
        )

    # Step 3: Gather completeness, contradiction, and policy conflict reasons
    missing_paths = check_profile_completeness(alert)
    blocker_reasons: list[str] = []
    blocker_paths: list[str] = []

    if missing_paths:
        blocker_reasons.append("missing_evidence")
        blocker_paths.extend(missing_paths)

    conflict_reasons, conflict_paths = check_contradictions_and_conflicts(alert)
    blocker_reasons.extend(conflict_reasons)
    blocker_paths.extend(conflict_paths)

    suspicious_matches = [
        r for r in rule_evaluations if r.state == "matched" and r.category == "suspicious"
    ]
    benign_matches = [
        r for r in rule_evaluations if r.state == "matched" and r.category == "benign_candidate"
    ]

    # Step 4: If any blocker exists, return needs_review while retaining suspicious rule matches
    if blocker_reasons:
        retained_rule_ids = tuple(sorted(r.rule_id for r in suspicious_matches))
        evidence: list[str] = []
        for r in suspicious_matches:
            evidence.extend(r.evidence_paths)
        evidence.extend(blocker_paths)
        baseline_disposition = "needs_review"
        review_reasons = list(sorted(set(blocker_reasons)))
        matched_rule_ids = retained_rule_ids
        evidence_paths = _dedupe_preserve_order(evidence)

    # Step 5: Simultaneous suspicious and benign match -> rule_conflict
    elif suspicious_matches and benign_matches:
        all_matched = suspicious_matches + benign_matches
        matched_rule_ids = tuple(sorted(r.rule_id for r in all_matched))
        evidence = []
        for r in all_matched:
            evidence.extend(r.evidence_paths)
        baseline_disposition = "needs_review"
        review_reasons = ["rule_conflict"]
        evidence_paths = _dedupe_preserve_order(evidence)

    # Step 6a: Suspicious match
    elif suspicious_matches:
        matched_rule_ids = tuple(sorted(r.rule_id for r in suspicious_matches))
        evidence = []
        for r in suspicious_matches:
            evidence.extend(r.evidence_paths)
        baseline_disposition = "suspicious"
        review_reasons = []
        evidence_paths = _dedupe_preserve_order(evidence)

    # Step 6b: Benign candidate match (with complete profile and no conflicts)
    elif benign_matches:
        matched_rule_ids = tuple(sorted(r.rule_id for r in benign_matches))
        evidence = []
        for r in benign_matches:
            evidence.extend(r.evidence_paths)
        baseline_disposition = "likely_benign"
        review_reasons = []
        evidence_paths = _dedupe_preserve_order(evidence)

    # Step 6c: Neither matched -> needs_review with no_decisive_rule
    else:
        matched_rule_ids = ()
        essential = [
            f"observations.{f}" for f in PROFILE_ESSENTIAL_ORDER.get(profile_key, ())
        ]
        baseline_disposition = "needs_review"
        review_reasons = ["no_decisive_rule"]
        evidence_paths = _dedupe_preserve_order(essential)

    # Step 7: Optional ML advisory disagreement escalation (INV-03, DESIGN.md, EXAMPLES L-N)
    final_disposition = baseline_disposition
    if (
        classifier_output is not None
        and baseline_disposition in ("suspicious", "likely_benign")
        and classifier_output.state == "succeeded"
        and classifier_output.support_status == "supported"
        and classifier_output.predicted_class in ("suspicious", "likely_benign")
        and classifier_output.predicted_class in classifier_output.supported_classes
        and classifier_output.predicted_class != baseline_disposition
    ):
        final_disposition = "needs_review"
        if "classifier_disagreement" not in review_reasons:
            review_reasons.append("classifier_disagreement")
        review_reasons.sort()

    return DecisionRecord(
        baseline_disposition=baseline_disposition,
        disposition=final_disposition,
        review_reasons=tuple(review_reasons),
        matched_rule_ids=matched_rule_ids,
        evidence_paths=evidence_paths,
        rule_evaluations=rule_evaluations,
        policy_version=POLICY_VERSION,
    )
