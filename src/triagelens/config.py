"""Configuration, component identities, and resource limits for TriageLens (P0-04, P3-02, P5, P6)."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

APPLICATION_VERSION = "0.1.0-demo"
SCHEMA_VERSION = "1.0"
RESULT_SCHEMA_VERSION = "1.0"
NORMALIZER_VERSION = "norm-v1"
RULESET_ID = "demo-v1"
RULESET_REVIEW_STATUS = "unvalidated_demo"
POLICY_VERSION = "policy-v1"
EXPLAIN_VERSION = "explain-v1"

DEFAULT_CLASSIFIER_ARTIFACT = "models/triagelens_linear_v1.json"
DEFAULT_SUMMARIZER_ENDPOINT = "http://127.0.0.1:11434"
DEFAULT_SUMMARIZER_MODEL = "qwen2.5:1.5b"

SUPPORTED_FAMILIES = frozenset({"authentication", "process", "network"})
SUPPORTED_RULESETS = frozenset({"demo-v1"})
SUPPORTED_OPTIONAL_MODES = frozenset({"permissive", "strict"})
SUPPORTED_BATCH_ERROR_POLICIES = frozenset({"continue", "abort"})


class ConfigurationError(ValueError):
    """Raised when operator-supplied run configuration or resource limits are invalid."""


@dataclass(frozen=True)
class RunConfig:
    """Immutable run configuration with explicit resource boundaries and optional model modes."""

    ruleset_id: str = RULESET_ID
    optional_mode: str = "permissive"
    batch_error_policy: str = "continue"
    overwrite: bool = False

    # Resource and ingestion limits (ARCHITECTURE.md, SECURITY.md)
    max_input_file_bytes: int = 100 * 1024 * 1024  # 100 MiB
    max_records_per_run: int = 10_000
    max_record_bytes: int = 1 * 1024 * 1024  # 1 MiB
    max_source_text_bytes: int = 16 * 1024  # 16 KiB
    max_json_depth: int = 8
    max_id_length: int = 256
    max_entity_length: int = 512

    # Optional classical classifier settings (P5)
    enable_classifier: bool = False
    classifier_artifact_path: str | None = None
    classifier_timeout_ms: int = 200

    # Optional local LLM summarizer settings (P6)
    enable_summarizer: bool = False
    summarizer_endpoint: str | None = None
    summarizer_model: str = DEFAULT_SUMMARIZER_MODEL
    summarizer_timeout_ms: int = 10_000

    def validate(self) -> None:
        """Validate configuration parameters before any alerts are processed."""
        if self.ruleset_id not in SUPPORTED_RULESETS:
            raise ConfigurationError(f"Unsupported ruleset_id: {self.ruleset_id!r}")
        if self.optional_mode not in SUPPORTED_OPTIONAL_MODES:
            raise ConfigurationError(f"Unsupported optional_mode: {self.optional_mode!r}")
        if self.batch_error_policy not in SUPPORTED_BATCH_ERROR_POLICIES:
            raise ConfigurationError(f"Unsupported batch_error_policy: {self.batch_error_policy!r}")

        for field_name in (
            "max_input_file_bytes",
            "max_records_per_run",
            "max_record_bytes",
            "max_source_text_bytes",
            "max_json_depth",
            "max_id_length",
            "max_entity_length",
            "classifier_timeout_ms",
            "summarizer_timeout_ms",
        ):
            val = getattr(self, field_name)
            if not isinstance(val, int) or isinstance(val, bool) or val <= 0:
                raise ConfigurationError(f"Limit {field_name} must be a positive integer")

        if self.max_record_bytes > self.max_input_file_bytes:
            raise ConfigurationError("max_record_bytes cannot exceed max_input_file_bytes")

        if self.summarizer_endpoint is not None:
            # SECURITY.md: Only explicit local loopback endpoints are permitted when configured
            allowed_prefixes = ("http://127.0.0.1:", "http://localhost:", "mock://")
            if not any(self.summarizer_endpoint.startswith(prefix) for prefix in allowed_prefixes):
                raise ConfigurationError(
                    "Optional summarizer_endpoint must bind to local loopback (127.0.0.1 or localhost)"
                )

        if not isinstance(self.summarizer_model, str) or not self.summarizer_model.strip():
            raise ConfigurationError("summarizer_model must be a non-empty string")

    def config_sha256(self) -> str:
        """Compute deterministic SHA-256 digest of semantic configuration (excluding local paths)."""
        payload: dict[str, object] = {
            "application_version": APPLICATION_VERSION,
            "schema_version": SCHEMA_VERSION,
            "result_schema_version": RESULT_SCHEMA_VERSION,
            "normalizer_version": NORMALIZER_VERSION,
            "ruleset_id": self.ruleset_id,
            "policy_version": POLICY_VERSION,
            "explain_version": EXPLAIN_VERSION,
            "optional_mode": self.optional_mode,
            "batch_error_policy": self.batch_error_policy,
            "max_input_file_bytes": self.max_input_file_bytes,
            "max_records_per_run": self.max_records_per_run,
            "max_record_bytes": self.max_record_bytes,
            "max_source_text_bytes": self.max_source_text_bytes,
            "max_json_depth": self.max_json_depth,
            "max_id_length": self.max_id_length,
            "max_entity_length": self.max_entity_length,
            "enable_classifier": self.enable_classifier,
            "classifier_timeout_ms": self.classifier_timeout_ms,
            "enable_summarizer": self.enable_summarizer,
            "summarizer_timeout_ms": self.summarizer_timeout_ms,
        }
        if self.enable_summarizer:
            payload["summarizer_model"] = self.summarizer_model
        canonical_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical_bytes).hexdigest()
