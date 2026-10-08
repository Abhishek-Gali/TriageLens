"""Deterministic template explanations, evidence resolution, and control-character escaping (P2-03, P3-01)."""

from __future__ import annotations

from triagelens.config import EXPLAIN_VERSION
from triagelens.contracts import DecisionRecord, NormalizedAlert, SummaryRecord


def sanitize_for_display(value: str) -> str:
    """Escape ASCII and C1 control characters so untrusted strings remain inert in output/terminals."""
    out: list[str] = []
    for ch in value:
        code = ord(ch)
        if code < 0x20 or code == 0x7F or (0x80 <= code <= 0x9F):
            out.append(f"\\x{code:02x}")
        else:
            out.append(ch)
    return "".join(out)


def verify_evidence_paths(alert: NormalizedAlert, decision: DecisionRecord) -> list[str]:
    """Return any evidence paths in the decision that fail to resolve on the normalized alert."""
    unresolved: list[str] = []
    for path in decision.evidence_paths:
        ok, _ = alert.resolve_path(path)
        if not ok:
            unresolved.append(path)
    return unresolved


def render_template_summary(alert: NormalizedAlert, decision: DecisionRecord) -> str:
    """Render a deterministic, cautious explanation from the frozen decision and normalized observations."""
    obs = alert.observations
    family = sanitize_for_display(alert.family)
    event_name = sanitize_for_display(alert.event_name)
    reasons = set(decision.review_reasons)

    # 1. Unsupported event pattern within a supported family (Case F)
    if "unsupported_pattern" in reasons:
        return (
            f"The supplied {family} alert reports event '{event_name}', which has no configured "
            f"profile in ruleset demo-v1. Disposition is needs_review (unsupported_pattern); "
            f"manual analyst inspection of the event schema is required."
        )

    # 2. Contradictory evidence or policy conflict blockers (Case D and process policy conflict)
    if "contradictory_evidence" in reasons or "policy_conflict" in reasons:
        parts: list[str] = []
        if "contradictory_evidence" in reasons:
            parts.append(
                "The supplied network alert asserts both destination_blocklisted=true and "
                "approved_destination=true (contradictory_evidence)."
            )
        if "policy_conflict" in reasons:
            parts.append(
                "The supplied process alert asserts both signature_status='unsigned' and "
                "approved_executable=true (policy_conflict)."
            )
        if "missing_evidence" in reasons:
            missing_list = [p for p in decision.evidence_paths if alert.resolve_path(p)[1] in (None, "unknown")]
            parts.append(
                f"Additionally, required evidence is missing or unknown ({', '.join(missing_list)})."
            )
        if decision.matched_rule_ids:
            parts.append(
                f"Suspicious rule match {', '.join(decision.matched_rule_ids)} is preserved."
            )
        parts.append(
            "Disposition is needs_review; verify the upstream source assertions before deciding."
        )
        return " ".join(parts)

    # 3. Incomplete evidence blocker (Case C)
    if "missing_evidence" in reasons:
        missing_fields: list[str] = []
        for path in decision.evidence_paths:
            _, val = alert.resolve_path(path)
            if val is None or (
                path in ("observations.signature_status", "observations.location_category")
                and val == "unknown"
            ):
                missing_fields.append(path)
        missing_str = ", ".join(missing_fields) if missing_fields else "required profile fields"
        retained = (
            f" Suspicious rule match {', '.join(decision.matched_rule_ids)} is retained."
            if decision.matched_rule_ids
            else ""
        )
        return (
            f"The supplied {family}/{event_name} alert has incomplete or unknown evidence in "
            f"{missing_str}.{retained} Disposition is needs_review (missing_evidence); "
            f"obtain the missing observation values to complete triage."
        )

    # 4. Classifier disagreement escalation (Case L)
    if "classifier_disagreement" in reasons:
        rules_str = ", ".join(decision.matched_rule_ids) if decision.matched_rule_ids else "baseline policy"
        return (
            f"Baseline rules ({rules_str}) evaluated the supplied {family}/{event_name} alert as "
            f"{decision.baseline_disposition}, but the optional advisory classifier disagreed. "
            f"Disposition is escalated to needs_review (classifier_disagreement) for analyst verification."
        )

    # 5. Decisive suspicious dispositions (Cases A, H, and NET-S01)
    if decision.disposition == "suspicious":
        rules_str = ", ".join(decision.matched_rule_ids)
        if alert.family == "authentication":
            return (
                f"The supplied alert reports {obs.get('failed_attempts')} failed attempts within "
                f"{obs.get('window_seconds')} seconds followed by success "
                f"(approved_origin={str(obs.get('approved_origin')).lower()}). "
                f"{rules_str} marks this sequence suspicious for investigation."
            )
        if alert.family == "process":
            return (
                f"The supplied alert reports an executable with signature_status='{obs.get('signature_status')}' "
                f"started from location_category='{obs.get('location_category')}'. "
                f"{rules_str} marks this process activity suspicious for investigation."
            )
        if alert.family == "network":
            return (
                f"The supplied alert reports {obs.get('connection_count')} connection(s) within "
                f"{obs.get('window_seconds')} seconds with destination_blocklisted=true. "
                f"{rules_str} marks this network summary suspicious for investigation."
            )

    # 6. Decisive likely_benign dispositions (Cases B, I, and NET-B01)
    if decision.disposition == "likely_benign":
        rules_str = ", ".join(decision.matched_rule_ids)
        if alert.family == "authentication":
            return (
                f"The supplied alert reports {obs.get('failed_attempts')} failed attempt(s) within "
                f"{obs.get('window_seconds')} seconds followed by success from an approved origin "
                f"(approved_origin=true). {rules_str} classifies this sequence as likely_benign."
            )
        if alert.family == "process":
            return (
                f"The supplied alert reports a signed, approved executable "
                f"(signature_status='signed', approved_executable=true) in a managed location "
                f"(location_category='managed'). {rules_str} classifies this process start as likely_benign."
            )
        if alert.family == "network":
            return (
                f"The supplied alert reports {obs.get('connection_count')} connection(s) within "
                f"{obs.get('window_seconds')} seconds to an approved, non-blocklisted destination. "
                f"{rules_str} classifies this network activity as likely_benign."
            )

    # 7. Remaining needs_review (no_decisive_rule / rule_conflict, e.g. Cases G and K)
    reason_str = ", ".join(decision.review_reasons) if decision.review_reasons else "no_decisive_rule"
    if alert.family == "authentication":
        return (
            f"The supplied authentication alert reports {obs.get('failed_attempts')} failed attempt(s) "
            f"in {obs.get('window_seconds')} seconds (success_after_failures="
            f"{str(obs.get('success_after_failures')).lower()}, approved_origin="
            f"{str(obs.get('approved_origin')).lower()}), which did not satisfy a decisive rule. "
            f"Disposition is needs_review ({reason_str})."
        )
    if alert.family == "process":
        return (
            f"The supplied process alert reports signature_status='{obs.get('signature_status')}', "
            f"location_category='{obs.get('location_category')}', and approved_executable="
            f"{str(obs.get('approved_executable')).lower()}, which did not satisfy a decisive rule. "
            f"Disposition is needs_review ({reason_str})."
        )
    if alert.family == "network":
        return (
            f"The supplied network alert reports {obs.get('connection_count')} connection(s) in "
            f"{obs.get('window_seconds')} seconds (destination_blocklisted="
            f"{str(obs.get('destination_blocklisted')).lower()}, approved_destination="
            f"{str(obs.get('approved_destination')).lower()}), which did not satisfy a decisive rule. "
            f"Disposition is needs_review ({reason_str})."
        )

    return f"Disposition is {decision.disposition} ({reason_str})."


def build_template_summary_record(alert: NormalizedAlert, decision: DecisionRecord) -> SummaryRecord:
    """Create the authoritative baseline template SummaryRecord."""
    text = render_template_summary(alert, decision)
    return SummaryRecord(
        text=text,
        source="template",
        template_text=text,
        version=EXPLAIN_VERSION,
        validation_state="valid",
        fallback_reason=None,
    )
