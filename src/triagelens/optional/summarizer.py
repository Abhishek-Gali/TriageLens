"""Restricted local LLM evidence packet builder, Ollama loopback adapter, candidate validator, and template fallback (P6-01 to P6-04)."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
import socket
from typing import Any, Callable
import urllib.error
import urllib.request

from triagelens.config import DEFAULT_SUMMARIZER_ENDPOINT, DEFAULT_SUMMARIZER_MODEL, EXPLAIN_VERSION
from triagelens.contracts import DecisionRecord, NormalizedAlert, SummaryRecord
from triagelens.explain import build_template_summary_record, sanitize_for_display

MAX_SUMMARY_CHARS = 512

# Claims that violate faithfulness / non-action / cautious-wording requirements (EXAMPLES.md, SECURITY.md)
_UNSUPPORTED_CLAIM_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "unsupported_incident_claim",
        re.compile(
            r"\b(stole\s+credentials|compromised\s+the\s+account|confirmed\s+breach|"
            r"exfiltrated\s+data|malware\s+executed|attacker\s+compromised|"
            r"compromised\s+the\s+host|account\s+was\s+compromised)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "autonomous_action_claim",
        re.compile(
            r"\b(isolated\s+the\s+host|blocked\s+the\s+ip|disabled\s+the\s+account|"
            r"executed\s+remediation|ticket\s+created|quarantined\s+the\s+file)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "tool_or_command_syntax",
        re.compile(
            r"(```|<tool_call>|os\.system|subprocess|curl\s+|wget\s+|powershell|cmd\.exe)",
            re.IGNORECASE,
        ),
    ),
)


@dataclass(frozen=True)
class RestrictedEvidencePacket:
    """Minimal sanitized packet sent to an optional local summarizer after the decision is frozen (INV-04).

    Strictly excludes source_text, entities, metadata, alert_id, and filesystem paths.
    """

    family: str
    event_name: str
    baseline_disposition: str
    disposition: str
    review_reasons: tuple[str, ...]
    matched_rule_ids: tuple[str, ...]
    cited_observations: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "event_name": self.event_name,
            "baseline_disposition": self.baseline_disposition,
            "disposition": self.disposition,
            "review_reasons": list(self.review_reasons),
            "matched_rule_ids": list(self.matched_rule_ids),
            "cited_observations": dict(self.cited_observations),
        }


def build_restricted_evidence_packet(
    alert: NormalizedAlert,
    decision: DecisionRecord,
) -> RestrictedEvidencePacket:
    """Construct the restricted evidence packet from the frozen decision and normalized observations."""
    cited: dict[str, Any] = {}
    for path in decision.evidence_paths:
        if path.startswith("observations."):
            key = path.split(".", 1)[1]
            val = alert.observations.get(key)
            if isinstance(val, str):
                cited[key] = sanitize_for_display(val)[:64]
            else:
                cited[key] = val

    return RestrictedEvidencePacket(
        family=sanitize_for_display(alert.family)[:32],
        event_name=sanitize_for_display(alert.event_name)[:64],
        baseline_disposition=decision.baseline_disposition,
        disposition=decision.disposition,
        review_reasons=decision.review_reasons,
        matched_rule_ids=decision.matched_rule_ids,
        cited_observations=cited,
    )


def validate_candidate_summary(
    candidate: Any,
    packet: RestrictedEvidencePacket,
) -> tuple[bool, str | None, str | None]:
    """Validate an untrusted candidate summary against length, disposition consistency, and faithfulness rules.

    Returns (is_valid, sanitized_text_or_none, rejection_reason_or_none).
    """
    if isinstance(candidate, dict):
        if set(candidate.keys()) != {"summary_text"}:
            return False, None, "unexpected_candidate_fields"
        candidate = candidate.get("summary_text")

    if not isinstance(candidate, str):
        return False, None, "candidate_not_string"

    sanitized = sanitize_for_display(candidate.strip())
    if not sanitized:
        return False, None, "empty_candidate_summary"
    if len(sanitized) > MAX_SUMMARY_CHARS:
        return False, sanitized[:MAX_SUMMARY_CHARS], "candidate_exceeds_max_length"

    for reason_code, pattern in _UNSUPPORTED_CLAIM_PATTERNS:
        if pattern.search(sanitized):
            return False, sanitized, reason_code

    lower_text = sanitized.lower()
    normalized_tokens = lower_text.replace("likely benign", "likely_benign").replace(
        "needs review", "needs_review"
    )
    # Disposition consistency check: candidate must mention the frozen disposition and must not claim an opposite verdict
    if packet.disposition not in normalized_tokens:
        return False, sanitized, "missing_frozen_disposition"

    if packet.disposition == "suspicious" and "likely_benign" in normalized_tokens:
        return False, sanitized, "contradicts_frozen_disposition"
    if packet.disposition == "likely_benign" and "suspicious" in normalized_tokens:
        return False, sanitized, "contradicts_frozen_disposition"
    if packet.disposition == "needs_review" and (
        "marked likely_benign" in normalized_tokens
        or "marked suspicious" in normalized_tokens
        or "is likely_benign" in normalized_tokens
        or "is suspicious" in normalized_tokens
    ):
        return False, sanitized, "contradicts_frozen_disposition"

    return True, sanitized, None


def verify_ollama_loopback_model(
    endpoint: str = DEFAULT_SUMMARIZER_ENDPOINT,
    model: str = DEFAULT_SUMMARIZER_MODEL,
    timeout_sec: float = 2.0,
) -> tuple[bool, str | None]:
    """Verify that the local loopback Ollama endpoint is reachable and has the requested model."""
    if not endpoint.startswith(("http://127.0.0.1:", "http://localhost:")):
        return False, "non_loopback_endpoint_rejected"

    tags_url = endpoint.rstrip("/") + "/api/tags"
    try:
        req = urllib.request.Request(tags_url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="strict"))
        models = [m.get("name", "") for m in payload.get("models", []) if isinstance(m, dict)]
        if model not in models and f"{model}:latest" not in models:
            return False, f"model_{model}_not_found_in_local_ollama"
        return True, None
    except Exception:
        return False, "local_llm_unavailable"


def make_ollama_loopback_generator(
    endpoint: str = DEFAULT_SUMMARIZER_ENDPOINT,
    model: str = DEFAULT_SUMMARIZER_MODEL,
    timeout_ms: int = 10_000,
) -> Callable[[RestrictedEvidencePacket], str]:
    """Create a loopback-only Ollama generator function for RestrictedEvidencePacket (P6-01, P6-02)."""
    if not endpoint.startswith(("http://127.0.0.1:", "http://localhost:")):
        raise ValueError("Summarizer endpoint must bind to local loopback (127.0.0.1 or localhost)")

    gen_url = endpoint.rstrip("/") + "/api/generate"
    timeout_sec = max(0.1, timeout_ms / 1000.0)

    def _generate(packet: RestrictedEvidencePacket) -> str:
        pkt_json = json.dumps(packet.to_dict(), sort_keys=True, separators=(",", ":"))
        system_instructions = (
            "You are a cautious security alert summary assistant. "
            "Write 1 or 2 short sentences (under 300 characters total) summarizing ONLY the "
            "facts in the JSON evidence packet.\n"
            "Sentence 1: Start with 'The supplied alert reports' and state the family, event_name, and cited_observations.\n"
            f"Sentence 2: End with 'Disposition is {packet.disposition}.' and mention matched_rule_ids or review_reasons if non-empty. "
            f"Use ONLY the disposition label '{packet.disposition}'; do not mention any other disposition words.\n"
            "Never claim an attacker stole credentials, compromised a host/account, or that remediation occurred."
        )
        body = json.dumps(
            {
                "model": model,
                "system": system_instructions,
                "prompt": f"Evidence packet: {pkt_json}\nTwo-sentence summary:",
                "stream": False,
                "options": {
                    "temperature": 0.0,
                    "seed": 42,
                    "num_predict": 75,
                },
            }
        ).encode("utf-8")

        req = urllib.request.Request(
            gen_url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
                raw = resp.read().decode("utf-8", errors="strict")
            parsed = json.loads(raw)
            return str(parsed.get("response", "")).strip()
        except (TimeoutError, socket.timeout) as exc:
            raise TimeoutError("Ollama loopback inference timed out") from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (TimeoutError, socket.timeout)):
                raise TimeoutError("Ollama loopback inference timed out") from exc
            raise RuntimeError("Ollama loopback connection failed") from exc

    return _generate


class LocalSummarizerAdapter:
    """Optional local summarizer with strict containment, candidate validation, and template fallback."""

    def __init__(
        self,
        enabled: bool = False,
        generator_fn: Callable[[RestrictedEvidencePacket], Any] | None = None,
        unavailable_reason: str | None = None,
        model_id: str | None = None,
    ) -> None:
        self.enabled = enabled
        self.generator_fn = generator_fn
        self.unavailable_reason = unavailable_reason
        self.model_id = model_id

    def summarize(
        self,
        alert: NormalizedAlert,
        decision: DecisionRecord,
    ) -> SummaryRecord:
        """Render template summary first, then optionally run and validate local summarizer."""
        baseline_summary = build_template_summary_record(alert, decision)
        if not self.enabled:
            return baseline_summary

        packet = build_restricted_evidence_packet(alert, decision)

        if self.generator_fn is None:
            return SummaryRecord(
                text=baseline_summary.template_text,
                source="template",
                template_text=baseline_summary.template_text,
                version=EXPLAIN_VERSION,
                validation_state="failed_fallback",
                fallback_reason=self.unavailable_reason or "local_llm_unavailable",
            )

        try:
            raw_candidate = self.generator_fn(packet)
        except TimeoutError:
            return SummaryRecord(
                text=baseline_summary.template_text,
                source="template",
                template_text=baseline_summary.template_text,
                version=EXPLAIN_VERSION,
                validation_state="failed_fallback",
                fallback_reason="summarizer_timeout",
            )
        except Exception:
            return SummaryRecord(
                text=baseline_summary.template_text,
                source="template",
                template_text=baseline_summary.template_text,
                version=EXPLAIN_VERSION,
                validation_state="failed_fallback",
                fallback_reason="summarizer_runtime_error",
            )

        is_valid, clean_text, rejection_reason = validate_candidate_summary(raw_candidate, packet)
        if not is_valid or clean_text is None:
            return SummaryRecord(
                text=baseline_summary.template_text,
                source="template",
                template_text=baseline_summary.template_text,
                version=EXPLAIN_VERSION,
                validation_state="rejected_fallback",
                fallback_reason=rejection_reason or "candidate_validation_failed",
                candidate_rejected_text=clean_text,
            )

        return SummaryRecord(
            text=clean_text,
            source="local_llm",
            template_text=baseline_summary.template_text,
            version=f"{EXPLAIN_VERSION}+{self.model_id}" if self.model_id else EXPLAIN_VERSION,
            validation_state="valid",
            fallback_reason=None,
        )
