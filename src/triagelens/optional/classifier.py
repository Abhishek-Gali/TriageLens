"""Optional classical classifier with safe JSON artifact loading and advisory-only output (P5-02, P5-04)."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import time
from typing import Any

from triagelens.contracts import KNOWN_PROFILES, ClassifierOutput, NormalizedAlert

FEATURE_SCHEMA_ID = "triagelens-features-v1"
ARTIFACT_FORMAT_ID = "triagelens-linear-v1"

FORBIDDEN_ARTIFACT_EXTENSIONS = frozenset(
    {".pkl", ".pickle", ".joblib", ".dill", ".marshal", ".pt", ".pth", ".bin", ".onnx", ".h5"}
)

ORDERED_FEATURE_NAMES: tuple[str, ...] = (
    "family_is_authentication",
    "family_is_process",
    "family_is_network",
    "auth_failed_attempts",
    "auth_window_seconds",
    "auth_success_after_failures",
    "auth_approved_origin",
    "proc_sig_signed",
    "proc_sig_unsigned",
    "proc_loc_managed",
    "proc_loc_user_writable",
    "proc_approved_executable",
    "net_connection_count",
    "net_window_seconds",
    "net_destination_blocklisted",
    "net_approved_destination",
)


class UnsafeModelArtifactError(ValueError):
    """Raised when a model artifact uses a prohibited format or fails schema/digest validation."""


def build_feature_vector(alert: NormalizedAlert) -> tuple[bool, list[float]]:
    """Build a versioned numeric feature vector from approved canonical fields only (INV-08).

    Never accesses alert_id, source_text, entities, metadata, source_severity, or labels.
    Returns (is_in_support, vector).
    """
    profile_key = (alert.family, alert.event_name)
    if profile_key not in KNOWN_PROFILES:
        return False, [0.0] * len(ORDERED_FEATURE_NAMES)

    obs = alert.observations
    # Require complete essential observations for in-support classification
    for req_key in KNOWN_PROFILES[profile_key]:
        val = obs.get(req_key)
        if val is None or (
            req_key in ("signature_status", "location_category") and val == "unknown"
        ):
            return False, [0.0] * len(ORDERED_FEATURE_NAMES)

    vec = [
        1.0 if alert.family == "authentication" else 0.0,
        1.0 if alert.family == "process" else 0.0,
        1.0 if alert.family == "network" else 0.0,
        float(obs.get("failed_attempts") or 0),
        float(obs.get("window_seconds") or 0) if alert.family == "authentication" else 0.0,
        1.0 if obs.get("success_after_failures") is True else 0.0,
        1.0 if obs.get("approved_origin") is True else 0.0,
        1.0 if obs.get("signature_status") == "signed" else 0.0,
        1.0 if obs.get("signature_status") == "unsigned" else 0.0,
        1.0 if obs.get("location_category") == "managed" else 0.0,
        1.0 if obs.get("location_category") == "user_writable" else 0.0,
        1.0 if obs.get("approved_executable") is True else 0.0,
        float(obs.get("connection_count") or 0),
        float(obs.get("window_seconds") or 0) if alert.family == "network" else 0.0,
        1.0 if obs.get("destination_blocklisted") is True else 0.0,
        1.0 if obs.get("approved_destination") is True else 0.0,
    ]
    return True, vec


@dataclass(frozen=True)
class VerifiedLinearModel:
    """Constrained linear classifier loaded from a verified JSON bundle without code execution."""

    model_id: str
    feature_schema_id: str
    supported_classes: tuple[str, ...]
    weights: tuple[float, ...]
    bias: float
    artifact_sha256: str
    simulated_delay_ms: int = 0


def load_verified_linear_model(artifact_path: str | Path) -> VerifiedLinearModel:
    """Load and verify a constrained JSON linear model artifact (SECURITY.md)."""
    path = Path(artifact_path)
    if any(ext in FORBIDDEN_ARTIFACT_EXTENSIONS for ext in path.suffixes):
        raise UnsafeModelArtifactError(
            f"Prohibited deserialization format ({''.join(path.suffixes)}); only constrained JSON is allowed"
        )
    if path.suffix.lower() != ".json":
        raise UnsafeModelArtifactError("Classifier artifact must have a .json extension")
    if not path.exists() or not path.is_file():
        raise FileNotFoundError("Classifier artifact file does not exist")

    raw_bytes = path.read_bytes()
    if len(raw_bytes) > 1024 * 1024:
        raise UnsafeModelArtifactError("Classifier artifact exceeds 1 MiB safety limit")

    try:
        data = json.loads(raw_bytes.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UnsafeModelArtifactError("Classifier artifact is not valid UTF-8 JSON") from exc

    if not isinstance(data, dict):
        raise UnsafeModelArtifactError("Classifier artifact root must be a JSON object")

    if data.get("format") != ARTIFACT_FORMAT_ID:
        raise UnsafeModelArtifactError(f"Unsupported model artifact format: {data.get('format')!r}")

    if data.get("feature_schema_id") != FEATURE_SCHEMA_ID:
        raise UnsafeModelArtifactError(
            f"Feature schema mismatch: expected {FEATURE_SCHEMA_ID!r}, got {data.get('feature_schema_id')!r}"
        )

    feature_names = data.get("feature_names")
    if not isinstance(feature_names, list) or tuple(feature_names) != ORDERED_FEATURE_NAMES:
        raise UnsafeModelArtifactError("Feature names or ordering do not match FEATURE_SCHEMA_ID")

    model_id = data.get("model_id")
    if not isinstance(model_id, str) or not model_id.strip():
        raise UnsafeModelArtifactError("Missing or invalid model_id in artifact")

    supported_classes = data.get("supported_classes")
    if (
        not isinstance(supported_classes, list)
        or not supported_classes
        or not all(c in ("suspicious", "likely_benign") for c in supported_classes)
    ):
        raise UnsafeModelArtifactError("supported_classes must be a non-empty subset of ['suspicious', 'likely_benign']")

    weights = data.get("weights")
    if (
        not isinstance(weights, list)
        or len(weights) != len(ORDERED_FEATURE_NAMES)
        or not all(isinstance(w, (int, float)) and not isinstance(w, bool) for w in weights)
    ):
        raise UnsafeModelArtifactError("weights must be a numeric array matching ORDERED_FEATURE_NAMES")

    bias = data.get("bias")
    if not isinstance(bias, (int, float)) or isinstance(bias, bool):
        raise UnsafeModelArtifactError("bias must be a numeric scalar")

    provenance = data.get("provenance")
    if not isinstance(provenance, dict) or not provenance.get("training_corpus_id"):
        raise UnsafeModelArtifactError("Model artifact must declare provenance.training_corpus_id")

    expected_digest = data.get("weights_sha256")
    weights_payload = json.dumps(
        {"weights": [float(w) for w in weights], "bias": float(bias)},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    actual_weights_digest = hashlib.sha256(weights_payload).hexdigest()
    if expected_digest is not None and expected_digest != actual_weights_digest:
        raise UnsafeModelArtifactError("Model weights_sha256 integrity check failed")

    simulated_delay_ms = int(data.get("simulated_delay_ms", 0))

    return VerifiedLinearModel(
        model_id=model_id.strip(),
        feature_schema_id=FEATURE_SCHEMA_ID,
        supported_classes=tuple(supported_classes),
        weights=tuple(float(w) for w in weights),
        bias=float(bias),
        artifact_sha256=hashlib.sha256(raw_bytes).hexdigest(),
        simulated_delay_ms=simulated_delay_ms,
    )


class AdvisoryClassifierAdapter:
    """Executes bounded advisory inference with timeout and support checks (INV-03, INV-07, INV-09)."""

    def __init__(
        self,
        enabled: bool = False,
        model: VerifiedLinearModel | None = None,
        timeout_ms: int = 200,
        unavailable_reason: str | None = None,
    ) -> None:
        self.enabled = enabled
        self.model = model
        self.timeout_ms = timeout_ms
        self.unavailable_reason = unavailable_reason

    def evaluate(self, alert: NormalizedAlert) -> ClassifierOutput:
        if not self.enabled:
            return ClassifierOutput(state="disabled")

        if self.model is None:
            return ClassifierOutput(
                state="unavailable",
                warning=self.unavailable_reason or "classifier_artifact_unavailable",
            )

        start_ns = time.monotonic_ns()
        if self.model.simulated_delay_ms > 0:
            if self.model.simulated_delay_ms > self.timeout_ms:
                return ClassifierOutput(
                    state="failed",
                    model_id=self.model.model_id,
                    feature_schema_id=self.model.feature_schema_id,
                    supported_classes=self.model.supported_classes,
                    warning="classifier_timeout",
                )

        in_support, features = build_feature_vector(alert)
        if not in_support:
            return ClassifierOutput(
                state="succeeded",
                model_id=self.model.model_id,
                feature_schema_id=self.model.feature_schema_id,
                predicted_class=None,
                raw_score=None,
                score_semantics=None,
                support_status="out_of_support",
                supported_classes=self.model.supported_classes,
                warning="incomplete_or_unsupported_profile_for_features",
            )

        margin = self.model.bias + sum(w * x for w, x in zip(self.model.weights, features))
        elapsed_ms = (time.monotonic_ns() - start_ns) / 1_000_000.0
        if elapsed_ms > self.timeout_ms:
            return ClassifierOutput(
                state="failed",
                model_id=self.model.model_id,
                feature_schema_id=self.model.feature_schema_id,
                supported_classes=self.model.supported_classes,
                warning="classifier_timeout",
            )

        predicted_class = "suspicious" if margin >= 0.0 else "likely_benign"
        if predicted_class not in self.model.supported_classes:
            return ClassifierOutput(
                state="succeeded",
                model_id=self.model.model_id,
                feature_schema_id=self.model.feature_schema_id,
                predicted_class=None,
                raw_score=round(float(margin), 6),
                score_semantics="uncalibrated",
                support_status="out_of_support",
                supported_classes=self.model.supported_classes,
                warning="predicted_class_not_in_supported_classes",
            )

        return ClassifierOutput(
            state="succeeded",
            model_id=self.model.model_id,
            feature_schema_id=self.model.feature_schema_id,
            predicted_class=predicted_class,
            raw_score=round(float(margin), 6),
            score_semantics="uncalibrated",
            support_status="supported",
            supported_classes=self.model.supported_classes,
            warning=None,
        )
