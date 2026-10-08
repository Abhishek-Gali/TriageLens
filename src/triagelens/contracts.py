"""Canonical input and result contracts and strict schema validation (P1-01)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import re
from typing import Any

from triagelens.config import (
    EXPLAIN_VERSION,
    RESULT_SCHEMA_VERSION,
    SCHEMA_VERSION,
    SUPPORTED_FAMILIES,
    RunConfig,
)

ALLOWED_TOP_LEVEL_KEYS = frozenset(
    {
        "schema_version",
        "alert_id",
        "observed_at",
        "family",
        "source",
        "event_name",
        "source_severity",
        "entities",
        "observations",
        "source_text",
        "metadata",
    }
)

REQUIRED_TOP_LEVEL_KEYS = (
    "schema_version",
    "alert_id",
    "observed_at",
    "family",
    "source",
    "event_name",
    "observations",
)

FORBIDDEN_LEAKAGE_KEYS = frozenset(
    {
        "ground_truth",
        "label",
        "labels",
        "expected_disposition",
        "underlying_scenario_state",
        "split",
        "scenario_family_id",
        "template_lineage",
        "scenario_id",
        "generator_seed",
    }
)

ALLOWED_SEVERITIES = frozenset({"low", "medium", "high", "critical", "unknown"})
ALLOWED_ENTITY_KEYS = frozenset({"host", "account", "process", "destination"})
ALLOWED_METADATA_KEYS = frozenset({"source_record_ref"})

KNOWN_PROFILES: dict[tuple[str, str], frozenset[str]] = {
    ("authentication", "login_sequence"): frozenset(
        {"failed_attempts", "window_seconds", "success_after_failures", "approved_origin"}
    ),
    ("process", "process_start"): frozenset(
        {"signature_status", "location_category", "approved_executable"}
    ),
    ("network", "connection_summary"): frozenset(
        {"connection_count", "window_seconds", "destination_blocklisted", "approved_destination"}
    ),
}

ALLOWED_SIGNATURE_STATUS = frozenset({"signed", "unsigned", "unknown"})
ALLOWED_LOCATION_CATEGORY = frozenset({"managed", "user_writable", "unknown"})

# Strict ISO-8601 timestamp with explicit UTC offset (Z or +HH:MM / -HH:MM)
_ISO8601_WITH_TZ_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$"
)


class _DuplicateKeyError(ValueError):
    """Internal marker for duplicate JSON object keys."""

    def __init__(self, key: str) -> None:
        super().__init__(f"Duplicate JSON key: {key}")
        self.key = key


class _NonFiniteNumberError(ValueError):
    """Internal marker for NaN / Infinity JSON constants."""

    def __init__(self, constant: str) -> None:
        super().__init__(f"Non-finite numeric value: {constant}")
        self.constant = constant


@dataclass(frozen=True)
class ValidationErrorRecord:
    """Bounded validation or processing error that never echoes raw untrusted input."""

    code: str
    message: str
    field: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "field": self.field,
        }


@dataclass(frozen=True)
class CanonicalAlert:
    """Validated canonical alert prior to normalization."""

    schema_version: str
    alert_id: str
    observed_at: str
    family: str
    source: str
    event_name: str
    observations: dict[str, Any]
    source_severity: str | None = None
    entities: dict[str, str | None] = field(default_factory=dict)
    source_text: str | None = None
    metadata: dict[str, str | None] = field(default_factory=dict)


@dataclass(frozen=True)
class NormalizedAlert:
    """Normalized alert with canonical UTC timestamp and stable field access."""

    schema_version: str
    alert_id: str
    observed_at_utc: str
    raw_observed_at: str
    family: str
    source: str
    event_name: str
    observations: dict[str, Any]
    source_severity: str | None
    entities: dict[str, str | None]
    source_text: str | None
    metadata: dict[str, str | None]

    def resolve_path(self, path: str) -> tuple[bool, Any]:
        """Resolve a canonical field path (e.g. 'observations.failed_attempts') for INV-06 checks."""
        parts = path.split(".")
        if len(parts) == 1:
            top = parts[0]
            if top == "observed_at":
                return True, self.observed_at_utc
            if hasattr(self, top) and top not in ("raw_observed_at", "observed_at_utc"):
                return True, getattr(self, top)
            return False, None
        if len(parts) == 2:
            group, key = parts
            if group == "observations":
                if key in self.observations:
                    return True, self.observations[key]
                # Even if omitted from dict, check if it's a valid profile observation field
                profile_keys = KNOWN_PROFILES.get((self.family, self.event_name), frozenset())
                if key in profile_keys:
                    return True, None
                return False, None
            if group == "entities" and key in ALLOWED_ENTITY_KEYS:
                return True, self.entities.get(key)
            if group == "metadata" and key in ALLOWED_METADATA_KEYS:
                return True, self.metadata.get(key)
        return False, None


@dataclass(frozen=True)
class RuleEvaluationRecord:
    """Structured result of evaluating a single rule against a normalized alert."""

    rule_id: str
    state: str  # matched | not_matched | not_evaluable | not_applicable
    category: str  # suspicious | benign_candidate
    evidence_paths: tuple[str, ...]
    missing_fields: tuple[str, ...]
    description: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "state": self.state,
            "category": self.category,
            "evidence_paths": list(self.evidence_paths),
            "missing_fields": list(self.missing_fields),
            "description": self.description,
        }


@dataclass(frozen=True)
class ClassifierOutput:
    """Advisory output and state of the optional classical classifier (INV-03, INV-07, INV-09)."""

    state: str  # disabled | unavailable | succeeded | failed
    model_id: str | None = None
    feature_schema_id: str | None = None
    predicted_class: str | None = None
    raw_score: float | None = None
    score_semantics: str | None = None  # Always 'uncalibrated' when score is present
    support_status: str | None = None  # supported | out_of_support | None
    supported_classes: tuple[str, ...] = ()
    warning: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "model_id": self.model_id,
            "feature_schema_id": self.feature_schema_id,
            "predicted_class": self.predicted_class,
            "raw_score": self.raw_score,
            "score_semantics": self.score_semantics,
            "support_status": self.support_status,
            "warning": self.warning,
        }


@dataclass(frozen=True)
class DecisionRecord:
    """Frozen triage decision produced exclusively by the deterministic policy (INV-03, INV-04)."""

    baseline_disposition: str  # suspicious | likely_benign | needs_review
    disposition: str  # suspicious | likely_benign | needs_review
    review_reasons: tuple[str, ...]
    matched_rule_ids: tuple[str, ...]
    evidence_paths: tuple[str, ...]
    rule_evaluations: tuple[RuleEvaluationRecord, ...]
    policy_version: str


@dataclass(frozen=True)
class SummaryRecord:
    """Explanation summary metadata and text with preserved template fallback (INV-04, INV-07)."""

    text: str | None
    source: str | None  # template | local_llm | None
    template_text: str | None
    version: str = EXPLAIN_VERSION
    validation_state: str = "valid"  # valid | rejected_fallback | failed_fallback | not_applicable
    fallback_reason: str | None = None
    candidate_rejected_text: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "source": self.source,
            "template_text": self.template_text,
            "version": self.version,
            "validation_state": self.validation_state,
            "fallback_reason": self.fallback_reason,
        }


@dataclass(frozen=True)
class TimingRecord:
    """Per-record monotonic timing measurements in nanoseconds."""

    total_ns: int
    baseline_ns: int
    classifier_ns: int = 0
    summarizer_ns: int = 0
    clock_semantics: str = "monotonic_ns"

    def to_dict(self) -> dict[str, Any]:
        return {
            "clock_semantics": self.clock_semantics,
            "total_ns": self.total_ns,
            "baseline_ns": self.baseline_ns,
            "classifier_ns": self.classifier_ns,
            "summarizer_ns": self.summarizer_ns,
        }


@dataclass(frozen=True)
class ProvenanceRecord:
    """Per-record processing provenance and component version identities (INV-06)."""

    input_record_sha256: str
    schema_version: str
    result_schema_version: str
    normalizer_version: str
    ruleset_id: str
    ruleset_sha256: str
    ruleset_review_status: str
    policy_version: str
    application_version: str
    config_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_record_sha256": self.input_record_sha256,
            "schema_version": self.schema_version,
            "result_schema_version": self.result_schema_version,
            "normalizer_version": self.normalizer_version,
            "ruleset_id": self.ruleset_id,
            "ruleset_sha256": self.ruleset_sha256,
            "ruleset_review_status": self.ruleset_review_status,
            "policy_version": self.policy_version,
            "application_version": self.application_version,
            "config_sha256": self.config_sha256,
        }


@dataclass(frozen=True)
class AlertResultRecord:
    """Complete canonical output record emitted for each input line (DESIGN.md)."""

    run_id: str
    record_index: int
    alert_id: str | None
    processing_status: str  # accepted | invalid | failed
    errors: tuple[ValidationErrorRecord, ...]
    baseline_disposition: str | None
    disposition: str | None
    review_reasons: tuple[str, ...]
    matched_rule_ids: tuple[str, ...]
    evidence_paths: tuple[str, ...]
    rule_evaluations: tuple[RuleEvaluationRecord, ...]
    provenance: ProvenanceRecord
    optional_classifier: ClassifierOutput
    summary: SummaryRecord
    timing: TimingRecord
    result_schema_version: str = RESULT_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "result_schema_version": self.result_schema_version,
            "run_id": self.run_id,
            "record_index": self.record_index,
            "alert_id": self.alert_id,
            "processing_status": self.processing_status,
            "errors": [e.to_dict() for e in self.errors],
            "baseline_disposition": self.baseline_disposition,
            "disposition": self.disposition,
            "review_reasons": list(self.review_reasons),
            "matched_rule_ids": list(self.matched_rule_ids),
            "evidence_paths": list(self.evidence_paths),
            "rule_evaluations": [r.to_dict() for r in self.rule_evaluations],
            "provenance": self.provenance.to_dict(),
            "optional_classifier": self.optional_classifier.to_dict(),
            "summary": self.summary.to_dict(),
            "summary_source": self.summary.source,
            "timing": self.timing.to_dict(),
        }


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for k, v in pairs:
        if k in result:
            raise _DuplicateKeyError(k)
        result[k] = v
    return result


def _reject_non_finite(constant: str) -> Any:
    raise _NonFiniteNumberError(constant)


def _compute_json_depth(obj: Any, current: int = 1) -> int:
    if isinstance(obj, dict):
        if not obj:
            return current
        return max(_compute_json_depth(v, current + 1) for v in obj.values())
    if isinstance(obj, list):
        if not obj:
            return current
        return max(_compute_json_depth(v, current + 1) for v in obj)
    return current


def _find_forbidden_keys(obj: Any, prefix: str = "") -> str | None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else k
            if k in FORBIDDEN_LEAKAGE_KEYS:
                return path
            nested = _find_forbidden_keys(v, path)
            if nested is not None:
                return nested
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            nested = _find_forbidden_keys(item, f"{prefix}[{idx}]")
            if nested is not None:
                return nested
    return None


def _is_strict_int(val: Any) -> bool:
    return isinstance(val, int) and not isinstance(val, bool)


def _is_bounded_str(val: Any, max_len: int, allow_empty: bool = False) -> bool:
    if not isinstance(val, str):
        return False
    if "\x00" in val:
        return False
    if not allow_empty and len(val.strip()) == 0:
        return False
    return len(val) <= max_len


def parse_and_validate_timestamp(ts_str: str) -> datetime | None:
    """Validate an ISO-8601 timestamp with explicit UTC offset and return UTC datetime."""
    if not isinstance(ts_str, str) or not _ISO8601_WITH_TZ_RE.match(ts_str):
        return None
    normalized = ts_str[:-1] + "+00:00" if ts_str.endswith("Z") else ts_str
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return None
    return dt.astimezone(timezone.utc)


def _validate_observations(
    family: str,
    event_name: str,
    observations: dict[str, Any],
    config: RunConfig,
) -> list[ValidationErrorRecord]:
    errors: list[ValidationErrorRecord] = []
    profile_key = (family, event_name)

    if profile_key not in KNOWN_PROFILES:
        # Known family with unknown event_name (e.g. Case F): ensure observations are primitive/bounded
        for k, v in observations.items():
            if not _is_bounded_str(k, config.max_id_length):
                errors.append(
                    ValidationErrorRecord(
                        code="invalid_observation_key",
                        message="Observation key exceeds length or contains invalid characters",
                        field=f"observations.{k[:32]}",
                    )
                )
                continue
            if v is not None and not isinstance(v, (str, int, float, bool)):
                errors.append(
                    ValidationErrorRecord(
                        code="invalid_type",
                        message="Unrecognized event profile observations must be primitive values",
                        field=f"observations.{k}",
                    )
                )
            elif isinstance(v, str) and len(v) > config.max_entity_length:
                errors.append(
                    ValidationErrorRecord(
                        code="value_too_long",
                        message="Observation string value exceeds maximum length",
                        field=f"observations.{k}",
                    )
                )
        return errors

    allowed_keys = KNOWN_PROFILES[profile_key]
    for k in observations:
        if k not in allowed_keys:
            errors.append(
                ValidationErrorRecord(
                    code="unknown_observation_field",
                    message=f"Unexpected observation field for profile {family}/{event_name}",
                    field=f"observations.{k[:64]}",
                )
            )

    if profile_key == ("authentication", "login_sequence"):
        fa = observations.get("failed_attempts")
        if fa is not None and (not _is_strict_int(fa) or fa < 0):
            errors.append(
                ValidationErrorRecord(
                    code="invalid_type",
                    message="observations.failed_attempts must be a nonnegative integer",
                    field="observations.failed_attempts",
                )
            )
        ws = observations.get("window_seconds")
        if ws is not None and (not _is_strict_int(ws) or ws < 1):
            errors.append(
                ValidationErrorRecord(
                    code="invalid_type",
                    message="observations.window_seconds must be a positive integer",
                    field="observations.window_seconds",
                )
            )
        saf = observations.get("success_after_failures")
        if saf is not None and not isinstance(saf, bool):
            errors.append(
                ValidationErrorRecord(
                    code="invalid_type",
                    message="observations.success_after_failures must be a boolean",
                    field="observations.success_after_failures",
                )
            )
        ao = observations.get("approved_origin")
        if ao is not None and not isinstance(ao, bool):
            errors.append(
                ValidationErrorRecord(
                    code="invalid_type",
                    message="observations.approved_origin must be a boolean",
                    field="observations.approved_origin",
                )
            )

    elif profile_key == ("process", "process_start"):
        sig = observations.get("signature_status")
        if sig is not None and (not isinstance(sig, str) or sig not in ALLOWED_SIGNATURE_STATUS):
            errors.append(
                ValidationErrorRecord(
                    code="invalid_type",
                    message="observations.signature_status must be signed, unsigned, or unknown",
                    field="observations.signature_status",
                )
            )
        loc = observations.get("location_category")
        if loc is not None and (not isinstance(loc, str) or loc not in ALLOWED_LOCATION_CATEGORY):
            errors.append(
                ValidationErrorRecord(
                    code="invalid_type",
                    message="observations.location_category must be managed, user_writable, or unknown",
                    field="observations.location_category",
                )
            )
        ae = observations.get("approved_executable")
        if ae is not None and not isinstance(ae, bool):
            errors.append(
                ValidationErrorRecord(
                    code="invalid_type",
                    message="observations.approved_executable must be a boolean",
                    field="observations.approved_executable",
                )
            )

    elif profile_key == ("network", "connection_summary"):
        cc = observations.get("connection_count")
        if cc is not None and (not _is_strict_int(cc) or cc < 0):
            errors.append(
                ValidationErrorRecord(
                    code="invalid_type",
                    message="observations.connection_count must be a nonnegative integer",
                    field="observations.connection_count",
                )
            )
        ws = observations.get("window_seconds")
        if ws is not None and (not _is_strict_int(ws) or ws < 1):
            errors.append(
                ValidationErrorRecord(
                    code="invalid_type",
                    message="observations.window_seconds must be a positive integer",
                    field="observations.window_seconds",
                )
            )
        db = observations.get("destination_blocklisted")
        if db is not None and not isinstance(db, bool):
            errors.append(
                ValidationErrorRecord(
                    code="invalid_type",
                    message="observations.destination_blocklisted must be a boolean",
                    field="observations.destination_blocklisted",
                )
            )
        ad = observations.get("approved_destination")
        if ad is not None and not isinstance(ad, bool):
            errors.append(
                ValidationErrorRecord(
                    code="invalid_type",
                    message="observations.approved_destination must be a boolean",
                    field="observations.approved_destination",
                )
            )

    return errors


def validate_raw_record(
    raw_bytes: bytes,
    is_oversized: bool,
    config: RunConfig,
    seen_alert_ids: set[str],
) -> tuple[CanonicalAlert | None, list[ValidationErrorRecord]]:
    """Validate a raw JSONL line into a CanonicalAlert or bounded validation errors."""
    if is_oversized or len(raw_bytes) > config.max_record_bytes:
        return None, [
            ValidationErrorRecord(
                code="oversized_record",
                message=f"Record exceeds maximum byte limit of {config.max_record_bytes} bytes",
                field=None,
            )
        ]

    try:
        text = raw_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None, [
            ValidationErrorRecord(
                code="invalid_utf8",
                message="Record is not valid UTF-8 text",
                field=None,
            )
        ]

    if len(text.strip()) == 0:
        return None, [
            ValidationErrorRecord(
                code="empty_record",
                message="Blank or whitespace-only line is not a valid alert record",
                field=None,
            )
        ]

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_non_finite,
        )
    except _DuplicateKeyError as exc:
        return None, [
            ValidationErrorRecord(
                code="duplicate_json_key",
                message="JSON object contains duplicate keys",
                field=exc.key[:64],
            )
        ]
    except _NonFiniteNumberError:
        return None, [
            ValidationErrorRecord(
                code="invalid_number",
                message="Non-finite numeric values (NaN/Infinity) are not allowed",
                field=None,
            )
        ]
    except RecursionError:
        return None, [
            ValidationErrorRecord(
                code="excessive_nesting",
                message=f"JSON nesting depth exceeds limit of {config.max_json_depth}",
                field=None,
            )
        ]
    except json.JSONDecodeError:
        return None, [
            ValidationErrorRecord(
                code="malformed_json",
                message="Line is not valid JSON",
                field=None,
            )
        ]

    if not isinstance(parsed, dict):
        return None, [
            ValidationErrorRecord(
                code="invalid_root_type",
                message="JSON record root must be an object",
                field=None,
            )
        ]

    try:
        depth = _compute_json_depth(parsed)
    except RecursionError:
        depth = config.max_json_depth + 1
    if depth > config.max_json_depth:
        return None, [
            ValidationErrorRecord(
                code="excessive_nesting",
                message=f"JSON nesting depth ({depth}) exceeds limit of {config.max_json_depth}",
                field=None,
            )
        ]

    forbidden = _find_forbidden_keys(parsed)
    if forbidden is not None:
        return None, [
            ValidationErrorRecord(
                code="forbidden_field",
                message="Evaluation label or split metadata field is prohibited in inference input",
                field=forbidden[:64],
            )
        ]

    errors: list[ValidationErrorRecord] = []

    for key in parsed:
        if key not in ALLOWED_TOP_LEVEL_KEYS:
            errors.append(
                ValidationErrorRecord(
                    code="unknown_field",
                    message="Unknown top-level field in canonical envelope",
                    field=str(key)[:64],
                )
            )

    for req_key in REQUIRED_TOP_LEVEL_KEYS:
        if req_key not in parsed or parsed[req_key] is None:
            errors.append(
                ValidationErrorRecord(
                    code="missing_required_field",
                    message=f"Required field {req_key!r} is missing or null",
                    field=req_key,
                )
            )

    if errors:
        return None, errors

    # Validate schema_version
    schema_version = parsed["schema_version"]
    if not isinstance(schema_version, str):
        errors.append(
            ValidationErrorRecord(
                code="invalid_type",
                message="schema_version must be a string",
                field="schema_version",
            )
        )
    elif schema_version != SCHEMA_VERSION:
        errors.append(
            ValidationErrorRecord(
                code="unsupported_schema_version",
                message=f"Unsupported schema_version; expected {SCHEMA_VERSION!r}",
                field="schema_version",
            )
        )

    # Validate alert_id
    alert_id = parsed["alert_id"]
    if not _is_bounded_str(alert_id, config.max_id_length):
        errors.append(
            ValidationErrorRecord(
                code="invalid_type" if not isinstance(alert_id, str) else "invalid_identifier",
                message=f"alert_id must be a non-empty string up to {config.max_id_length} chars",
                field="alert_id",
            )
        )
    elif alert_id in seen_alert_ids:
        errors.append(
            ValidationErrorRecord(
                code="duplicate_alert_id",
                message="Duplicate alert_id within batch run; first occurrence retained",
                field="alert_id",
            )
        )

    # Validate observed_at
    observed_at = parsed["observed_at"]
    if not isinstance(observed_at, str):
        errors.append(
            ValidationErrorRecord(
                code="invalid_type",
                message="observed_at must be an ISO-8601 string",
                field="observed_at",
            )
        )
    elif parse_and_validate_timestamp(observed_at) is None:
        errors.append(
            ValidationErrorRecord(
                code="invalid_timestamp",
                message="observed_at must be a valid ISO-8601 timestamp with explicit UTC offset",
                field="observed_at",
            )
        )

    # Validate family (DESIGN.md: unknown family -> unsupported_family)
    family = parsed["family"]
    if not isinstance(family, str):
        errors.append(
            ValidationErrorRecord(
                code="invalid_type",
                message="family must be a string",
                field="family",
            )
        )
    elif family not in SUPPORTED_FAMILIES:
        errors.append(
            ValidationErrorRecord(
                code="unsupported_family",
                message="Unsupported alert family; supported families are authentication, process, network",
                field="family",
            )
        )

    # Validate source
    source = parsed["source"]
    if not _is_bounded_str(source, config.max_id_length):
        errors.append(
            ValidationErrorRecord(
                code="invalid_type" if not isinstance(source, str) else "invalid_identifier",
                message=f"source must be a non-empty string up to {config.max_id_length} chars",
                field="source",
            )
        )

    # Validate event_name
    event_name = parsed["event_name"]
    if not _is_bounded_str(event_name, config.max_id_length):
        errors.append(
            ValidationErrorRecord(
                code="invalid_type" if not isinstance(event_name, str) else "invalid_identifier",
                message=f"event_name must be a non-empty string up to {config.max_id_length} chars",
                field="event_name",
            )
        )

    # Validate optional source_severity
    source_severity = parsed.get("source_severity")
    if source_severity is not None:
        if not isinstance(source_severity, str) or source_severity not in ALLOWED_SEVERITIES:
            errors.append(
                ValidationErrorRecord(
                    code="invalid_type",
                    message="source_severity must be low, medium, high, critical, or unknown",
                    field="source_severity",
                )
            )

    # Validate optional entities
    entities_raw = parsed.get("entities")
    entities_clean: dict[str, str | None] = {}
    if entities_raw is not None:
        if not isinstance(entities_raw, dict):
            errors.append(
                ValidationErrorRecord(
                    code="invalid_type",
                    message="entities must be an object",
                    field="entities",
                )
            )
        else:
            for k, v in entities_raw.items():
                if k not in ALLOWED_ENTITY_KEYS:
                    errors.append(
                        ValidationErrorRecord(
                            code="unknown_field",
                            message="Unknown field in entities",
                            field=f"entities.{str(k)[:32]}",
                        )
                    )
                elif v is not None and not _is_bounded_str(v, config.max_entity_length):
                    errors.append(
                        ValidationErrorRecord(
                            code="invalid_type",
                            message=f"Entity {k!r} must be a non-empty string up to {config.max_entity_length} chars",
                            field=f"entities.{k}",
                        )
                    )
                else:
                    entities_clean[k] = v

    # Validate optional source_text
    source_text = parsed.get("source_text")
    if source_text is not None:
        if not isinstance(source_text, str) or "\x00" in source_text:
            errors.append(
                ValidationErrorRecord(
                    code="invalid_type",
                    message="source_text must be a valid string without NUL bytes",
                    field="source_text",
                )
            )
        elif (
            len(source_text) > config.max_source_text_bytes
            or len(source_text.encode("utf-8")) > config.max_source_text_bytes
        ):
            errors.append(
                ValidationErrorRecord(
                    code="value_too_long",
                    message=f"source_text exceeds limit of {config.max_source_text_bytes} bytes/chars",
                    field="source_text",
                )
            )

    # Validate optional metadata
    metadata_raw = parsed.get("metadata")
    metadata_clean: dict[str, str | None] = {}
    if metadata_raw is not None:
        if not isinstance(metadata_raw, dict):
            errors.append(
                ValidationErrorRecord(
                    code="invalid_type",
                    message="metadata must be an object",
                    field="metadata",
                )
            )
        else:
            for k, v in metadata_raw.items():
                if k not in ALLOWED_METADATA_KEYS:
                    errors.append(
                        ValidationErrorRecord(
                            code="unknown_field",
                            message="Only metadata.source_record_ref is permitted in schema 1.0",
                            field=f"metadata.{str(k)[:32]}",
                        )
                    )
                elif v is not None and not _is_bounded_str(v, config.max_entity_length):
                    errors.append(
                        ValidationErrorRecord(
                            code="invalid_type",
                            message="metadata.source_record_ref must be a non-empty bounded string",
                            field="metadata.source_record_ref",
                        )
                    )
                else:
                    metadata_clean[k] = v

    # Validate observations
    observations = parsed["observations"]
    if not isinstance(observations, dict):
        errors.append(
            ValidationErrorRecord(
                code="invalid_type",
                message="observations must be an object",
                field="observations",
            )
        )
    elif isinstance(family, str) and family in SUPPORTED_FAMILIES and isinstance(event_name, str):
        errors.extend(_validate_observations(family, event_name, observations, config))

    if errors:
        return None, errors

    seen_alert_ids.add(alert_id)
    return (
        CanonicalAlert(
            schema_version=schema_version,
            alert_id=alert_id,
            observed_at=observed_at,
            family=family,
            source=source,
            event_name=event_name,
            observations=dict(observations),
            source_severity=source_severity,
            entities=entities_clean,
            source_text=source_text,
            metadata=metadata_clean,
        ),
        [],
    )
