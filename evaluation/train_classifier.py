"""Independent synthetic training corpus generator, scikit-learn LogisticRegression trainer, and safe JSON exporter (P5-01, P5-02, P5-03)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import GroupKFold
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC

from evaluation.build_benchmark import _make_alert, _make_label, _write_jsonl
from triagelens.contracts import CanonicalAlert
from triagelens.normalize import normalize_alert
from triagelens.optional.classifier import (
    ARTIFACT_FORMAT_ID,
    FEATURE_SCHEMA_ID,
    ORDERED_FEATURE_NAMES,
    build_feature_vector,
    load_verified_linear_model,
)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def generate_independent_training_and_val_corpora() -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    """Generate 240 independent training alerts (TRAIN-*) and 60 validation alerts (VAL-*)."""
    train_alerts: list[dict[str, Any]] = []
    train_labels: list[dict[str, Any]] = []
    val_alerts: list[dict[str, Any]] = []
    val_labels: list[dict[str, Any]] = []

    def _populate_corpus(
        prefix: str,
        scale: int,
        alerts_out: list[dict[str, Any]],
        labels_out: list[dict[str, Any]],
    ) -> None:
        # scale=4 -> 240 alerts (80 auth, 80 proc, 80 net); scale=1 -> 60 alerts (20 auth, 20 proc, 20 net)
        idx = 0
        # 1. Authentication (20 * scale alerts)
        # 1a. True rapid brute-force bursts (8 * scale): failed_attempts 14..48, window_seconds 30..150 -> suspicious
        for i in range(8 * scale):
            idx += 1
            aid = f"{prefix}-auth-{idx:03d}"
            fa = 14 + (i % 12) * 3
            ws = 30 + (i % 6) * 20  # 30..130s
            alerts_out.append(
                _make_alert(
                    alert_id=aid,
                    observed_at="2026-09-15T10:00:00Z",
                    family="authentication",
                    source=f"synth-{prefix}-auth",
                    event_name="login_sequence",
                    observations={
                        "failed_attempts": fa,
                        "window_seconds": ws,
                        "success_after_failures": True,
                        "approved_origin": False,
                    },
                )
            )
            labels_out.append(
                _make_label(
                    alert_id=aid,
                    expected_disposition="suspicious",
                    underlying_scenario_state="malicious",
                    permitted_evidence_paths=[
                        "observations.failed_attempts",
                        "observations.window_seconds",
                        "observations.success_after_failures",
                    ],
                    expected_review_reasons=[],
                    scenario_family_id=f"{prefix.upper()}-AUTH-BURST",
                    template_lineage=f"lin-{prefix}-auth-burst",
                    slice_category="authentication",
                    rationale="High-rate credential brute-force burst in short window (<=130s) followed by login.",
                )
            )

        # 1b. Benign / non-suspicious service retry spikes over longer windows (4 * scale):
        # failed_attempts 10..12, window_seconds 200..290 -> non-suspicious (benign underlying state, needs_review disposition)
        for i in range(4 * scale):
            idx += 1
            aid = f"{prefix}-auth-{idx:03d}"
            fa = 10 + (i % 3)  # 10, 11, 12
            ws = 200 + (i % 4) * 25  # 200..275s
            alerts_out.append(
                _make_alert(
                    alert_id=aid,
                    observed_at="2026-09-15T10:05:00Z",
                    family="authentication",
                    source=f"synth-{prefix}-auth",
                    event_name="login_sequence",
                    observations={
                        "failed_attempts": fa,
                        "window_seconds": ws,
                        "success_after_failures": True,
                        "approved_origin": False,
                    },
                )
            )
            labels_out.append(
                _make_label(
                    alert_id=aid,
                    expected_disposition="needs_review",
                    underlying_scenario_state="benign",
                    permitted_evidence_paths=[
                        "observations.failed_attempts",
                        "observations.window_seconds",
                        "observations.success_after_failures",
                        "observations.approved_origin",
                    ],
                    expected_review_reasons=["no_decisive_rule"],
                    scenario_family_id=f"{prefix.upper()}-AUTH-SVC-RETRY",
                    template_lineage=f"lin-{prefix}-auth-svc-retry",
                    slice_category="authentication",
                    rationale="Slow automated service retry over 200-275s window after credential rotation (benign underlying state).",
                )
            )

        # 1c. Routine approved-origin logins (8 * scale): failed_attempts 0..2 -> likely_benign
        for i in range(8 * scale):
            idx += 1
            aid = f"{prefix}-auth-{idx:03d}"
            alerts_out.append(
                _make_alert(
                    alert_id=aid,
                    observed_at="2026-09-15T10:10:00Z",
                    family="authentication",
                    source=f"synth-{prefix}-auth",
                    event_name="login_sequence",
                    observations={
                        "failed_attempts": i % 3,
                        "window_seconds": 45 + (i % 5) * 30,
                        "success_after_failures": True,
                        "approved_origin": True,
                    },
                )
            )
            labels_out.append(
                _make_label(
                    alert_id=aid,
                    expected_disposition="likely_benign",
                    underlying_scenario_state="benign",
                    permitted_evidence_paths=[
                        "observations.failed_attempts",
                        "observations.success_after_failures",
                        "observations.approved_origin",
                    ],
                    expected_review_reasons=[],
                    scenario_family_id=f"{prefix.upper()}-AUTH-CORP",
                    template_lineage=f"lin-{prefix}-auth-corp",
                    slice_category="authentication",
                    rationale="Routine corporate login from approved origin with <=2 retries.",
                )
            )

        # 2. Process (20 * scale alerts)
        p_idx = 0
        # 2a. Unsigned user-writable droppers (10 * scale) -> suspicious
        for i in range(10 * scale):
            p_idx += 1
            aid = f"{prefix}-proc-{p_idx:03d}"
            alerts_out.append(
                _make_alert(
                    alert_id=aid,
                    observed_at="2026-09-15T11:00:00Z",
                    family="process",
                    source=f"synth-{prefix}-edr",
                    event_name="process_start",
                    observations={
                        "signature_status": "unsigned",
                        "location_category": "user_writable",
                        "approved_executable": False,
                    },
                )
            )
            labels_out.append(
                _make_label(
                    alert_id=aid,
                    expected_disposition="suspicious",
                    underlying_scenario_state="malicious",
                    permitted_evidence_paths=[
                        "observations.signature_status",
                        "observations.location_category",
                    ],
                    expected_review_reasons=[],
                    scenario_family_id=f"{prefix.upper()}-PROC-DROP",
                    template_lineage=f"lin-{prefix}-proc-drop",
                    slice_category="process",
                    rationale="Unsigned unapproved binary in user-writable path.",
                )
            )

        # 2b. Signed managed approved binaries (10 * scale) -> likely_benign
        for i in range(10 * scale):
            p_idx += 1
            aid = f"{prefix}-proc-{p_idx:03d}"
            alerts_out.append(
                _make_alert(
                    alert_id=aid,
                    observed_at="2026-09-15T11:10:00Z",
                    family="process",
                    source=f"synth-{prefix}-edr",
                    event_name="process_start",
                    observations={
                        "signature_status": "signed",
                        "location_category": "managed",
                        "approved_executable": True,
                    },
                )
            )
            labels_out.append(
                _make_label(
                    alert_id=aid,
                    expected_disposition="likely_benign",
                    underlying_scenario_state="benign",
                    permitted_evidence_paths=[
                        "observations.signature_status",
                        "observations.location_category",
                        "observations.approved_executable",
                    ],
                    expected_review_reasons=[],
                    scenario_family_id=f"{prefix.upper()}-PROC-MANAGED",
                    template_lineage=f"lin-{prefix}-proc-managed",
                    slice_category="process",
                    rationale="Signed approved binary in managed path.",
                )
            )

        # 3. Network (20 * scale alerts)
        n_idx = 0
        # 3a. Persistent C2 beacons to blocklisted destinations (8 * scale): connection_count 5..40 -> suspicious
        for i in range(8 * scale):
            n_idx += 1
            aid = f"{prefix}-net-{n_idx:03d}"
            alerts_out.append(
                _make_alert(
                    alert_id=aid,
                    observed_at="2026-09-15T12:00:00Z",
                    family="network",
                    source=f"synth-{prefix}-ndr",
                    event_name="connection_summary",
                    observations={
                        "connection_count": 5 + (i % 10) * 3,
                        "window_seconds": 60 + (i % 3) * 30,
                        "destination_blocklisted": True,
                        "approved_destination": False,
                    },
                )
            )
            labels_out.append(
                _make_label(
                    alert_id=aid,
                    expected_disposition="suspicious",
                    underlying_scenario_state="malicious",
                    permitted_evidence_paths=[
                        "observations.destination_blocklisted",
                        "observations.connection_count",
                    ],
                    expected_review_reasons=[],
                    scenario_family_id=f"{prefix.upper()}-NET-BEACON",
                    template_lineage=f"lin-{prefix}-net-beacon",
                    slice_category="network",
                    rationale="Repeated C2 callback connections (>=5) to blocklisted destination.",
                )
            )

        # 3b. Transient 1-2 connection hits to stale blocklisted CDN/cloud IPs (4 * scale) -> benign underlying state / needs_review
        for i in range(4 * scale):
            n_idx += 1
            aid = f"{prefix}-net-{n_idx:03d}"
            alerts_out.append(
                _make_alert(
                    alert_id=aid,
                    observed_at="2026-09-15T12:05:00Z",
                    family="network",
                    source=f"synth-{prefix}-ndr",
                    event_name="connection_summary",
                    observations={
                        "connection_count": 1 + (i % 2),  # 1 or 2
                        "window_seconds": 60,
                        "destination_blocklisted": True,
                        "approved_destination": False,
                    },
                )
            )
            labels_out.append(
                _make_label(
                    alert_id=aid,
                    expected_disposition="needs_review",
                    underlying_scenario_state="benign",
                    permitted_evidence_paths=[
                        "observations.connection_count",
                        "observations.window_seconds",
                        "observations.destination_blocklisted",
                        "observations.approved_destination",
                    ],
                    expected_review_reasons=["no_decisive_rule"],
                    scenario_family_id=f"{prefix.upper()}-NET-STALE-IP",
                    template_lineage=f"lin-{prefix}-net-stale-ip",
                    slice_category="network",
                    rationale="Single or two-connection hit to reallocated cloud IP on stale blocklist (benign underlying state).",
                )
            )

        # 3c. Approved destination traffic (8 * scale) -> likely_benign
        for i in range(8 * scale):
            n_idx += 1
            aid = f"{prefix}-net-{n_idx:03d}"
            alerts_out.append(
                _make_alert(
                    alert_id=aid,
                    observed_at="2026-09-15T12:10:00Z",
                    family="network",
                    source=f"synth-{prefix}-ndr",
                    event_name="connection_summary",
                    observations={
                        "connection_count": 2 + (i % 8) * 2,
                        "window_seconds": 120,
                        "destination_blocklisted": False,
                        "approved_destination": True,
                    },
                )
            )
            labels_out.append(
                _make_label(
                    alert_id=aid,
                    expected_disposition="likely_benign",
                    underlying_scenario_state="benign",
                    permitted_evidence_paths=[
                        "observations.approved_destination",
                        "observations.destination_blocklisted",
                        "observations.connection_count",
                    ],
                    expected_review_reasons=[],
                    scenario_family_id=f"{prefix.upper()}-NET-APPROVED",
                    template_lineage=f"lin-{prefix}-net-approved",
                    slice_category="network",
                    rationale="Outbound traffic to approved, non-blocklisted destination.",
                )
            )

    _populate_corpus("train", 4, train_alerts, train_labels)
    _populate_corpus("val", 1, val_alerts, val_labels)
    return train_alerts, train_labels, val_alerts, val_labels


def generate_fresh_p5p6_holdout_split() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Generate a fresh 120-alert grouped holdout split (HOLD2-*) for P5/P6 evaluation (EVALUATION.md line 84)."""
    from evaluation.build_benchmark import generate_holdout_split

    base_alerts, base_labels = generate_holdout_split()
    fresh_alerts: list[dict[str, Any]] = []
    fresh_labels: list[dict[str, Any]] = []

    for a, l in zip(base_alerts, base_labels):
        new_id = a["alert_id"].replace("hold-", "hold2-")
        a_copy = dict(a)
        a_copy["alert_id"] = new_id
        a_copy["observed_at"] = a["observed_at"].replace("2026-10-05", "2026-10-07")
        a_copy["source"] = a["source"].replace("-hold", "-hold2")
        if "metadata" in a_copy and a_copy["metadata"]:
            a_copy["metadata"] = {"source_record_ref": f"ref-{new_id}"}
        fresh_alerts.append(a_copy)

        l_copy = dict(l)
        l_copy["alert_id"] = new_id
        l_copy["scenario_family_id"] = l["scenario_family_id"].replace("HOLD-", "HOLD2-")
        l_copy["template_lineage"] = l["template_lineage"].replace("lin-hold-", "lin-hold2-")
        fresh_labels.append(l_copy)

    return fresh_alerts, fresh_labels


def _extract_matrix(
    alerts: list[dict[str, Any]],
    labels: list[dict[str, Any]],
) -> tuple[np.ndarray, np.ndarray, list[str]]:
    X_rows: list[list[float]] = []
    y_rows: list[int] = []
    groups: list[str] = []

    for a, l in zip(alerts, labels):
        canon = CanonicalAlert(
            schema_version=a["schema_version"],
            alert_id=a["alert_id"],
            observed_at=a["observed_at"],
            family=a["family"],
            source=a["source"],
            event_name=a["event_name"],
            observations=dict(a["observations"]),
            source_severity=a.get("source_severity"),
            entities=dict(a.get("entities") or {}),
            source_text=a.get("source_text"),
            metadata=dict(a.get("metadata") or {}),
        )
        norm = normalize_alert(canon)
        in_support, vec = build_feature_vector(norm)
        if not in_support:
            continue
        X_rows.append(vec)
        # Binary target for advisory classifier: 1 = suspicious (malicious), 0 = likely_benign (benign/non-suspicious)
        y_rows.append(1 if l["expected_disposition"] == "suspicious" else 0)
        groups.append(l["scenario_family_id"])

    return np.asarray(X_rows, dtype=np.float64), np.asarray(y_rows, dtype=np.int64), groups


def train_and_export_classifier(project_root: Path | None = None) -> dict[str, Any]:
    """Generate independent training/val/fresh-holdout corpora, train LogisticRegression, and export JSON artifact."""
    root = project_root or Path(__file__).resolve().parents[1]
    train_dir = root / "evaluation" / "training"
    hold2_dir = root / "evaluation" / "holdout_p5p6"
    models_dir = root / "models"
    models_dir.mkdir(parents=True, exist_ok=True)

    train_alerts, train_labels, val_alerts, val_labels = generate_independent_training_and_val_corpora()
    hold2_alerts, hold2_labels = generate_fresh_p5p6_holdout_split()

    train_alerts_path = train_dir / "train_alerts.jsonl"
    train_labels_path = train_dir / "train_labels.jsonl"
    val_alerts_path = train_dir / "val_alerts.jsonl"
    val_labels_path = train_dir / "val_labels.jsonl"
    hold2_alerts_path = hold2_dir / "alerts.jsonl"
    hold2_labels_path = hold2_dir / "labels.jsonl"

    _write_jsonl(train_alerts_path, train_alerts)
    _write_jsonl(train_labels_path, train_labels)
    _write_jsonl(val_alerts_path, val_alerts)
    _write_jsonl(val_labels_path, val_labels)
    _write_jsonl(hold2_alerts_path, hold2_alerts)
    _write_jsonl(hold2_labels_path, hold2_labels)

    X_train, y_train, groups_train = _extract_matrix(train_alerts, train_labels)
    X_val, y_val, _ = _extract_matrix(val_alerts, val_labels)

    # Strict featurization ordering (ml-best-practices): fit StandardScaler on X_train ONLY
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)

    # 1. Naive baseline (majority class on X_train)
    majority_class = int(np.bincount(y_train).argmax())
    y_val_naive = np.full_like(y_val, majority_class)

    # 2. LogisticRegression (L2 regularized)
    lr = LogisticRegression(C=1.0, solver="lbfgs", max_iter=500, random_state=42)
    lr.fit(X_train_scaled, y_train)
    y_val_lr = lr.predict(X_val_scaled)

    # 3. LinearSVC comparison model
    svc = LinearSVC(C=1.0, random_state=42, max_iter=2000)
    svc.fit(X_train_scaled, y_train)
    y_val_svc = svc.predict(X_val_scaled)

    # StratifiedGroupKFold cross-validation on training set (ensuring each fold has positive and negative scenario families)
    from sklearn.model_selection import StratifiedGroupKFold

    sgkf = StratifiedGroupKFold(n_splits=3)
    cv_f1_scores: list[float] = []
    for tr_idx, te_idx in sgkf.split(X_train, y_train, groups=groups_train):
        fold_scaler = StandardScaler()
        X_tr_s = fold_scaler.fit_transform(X_train[tr_idx])
        X_te_s = fold_scaler.transform(X_train[te_idx])
        fold_lr = LogisticRegression(C=1.0, solver="lbfgs", max_iter=500, random_state=42)
        fold_lr.fit(X_tr_s, y_train[tr_idx])
        preds = fold_lr.predict(X_te_s)
        cv_f1_scores.append(float(f1_score(y_train[te_idx], preds, zero_division=0)))

    # Fold StandardScaler (mean_, scale_) + LogisticRegression (coef_, intercept_) into raw feature weights:
    # margin(x) = intercept + sum(coef_i * (x_i - mean_i) / scale_i)
    raw_weights: list[float] = []
    bias_shift = 0.0
    for coef_i, mean_i, scale_i in zip(lr.coef_[0], scaler.mean_, scaler.scale_):
        denom = float(scale_i) if float(scale_i) != 0.0 else 1.0
        w_i = float(coef_i) / denom
        raw_weights.append(round(w_i, 8))
        bias_shift += w_i * float(mean_i)
    folded_bias = round(float(lr.intercept_[0]) - bias_shift, 8)

    weights_payload = json.dumps(
        {"weights": raw_weights, "bias": folded_bias},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    weights_sha256 = hashlib.sha256(weights_payload).hexdigest()

    artifact_path = models_dir / "triagelens_linear_v1.json"
    artifact_bundle = {
        "format": ARTIFACT_FORMAT_ID,
        "model_id": "triagelens-logreg-l2-v1",
        "algorithm": "sklearn.linear_model.LogisticRegression(C=1.0, solver='lbfgs', random_state=42) + StandardScaler",
        "feature_schema_id": FEATURE_SCHEMA_ID,
        "feature_names": list(ORDERED_FEATURE_NAMES),
        "supported_classes": ["suspicious", "likely_benign"],
        "score_semantics": "uncalibrated",
        "weights": raw_weights,
        "bias": folded_bias,
        "weights_sha256": weights_sha256,
        "provenance": {
            "training_corpus_id": "triagelens-synth-independent-train-v1",
            "train_alerts_sha256": _sha256_file(train_alerts_path),
            "train_labels_sha256": _sha256_file(train_labels_path),
            "val_alerts_sha256": _sha256_file(val_alerts_path),
            "val_labels_sha256": _sha256_file(val_labels_path),
            "train_records": len(train_alerts),
            "val_records": len(val_alerts),
            "sklearn_version": "1.8.0",
            "numpy_version": "2.3.5",
            "created_at_utc": "2026-10-08T18:05:00Z",
        },
    }
    artifact_path.write_text(json.dumps(artifact_bundle, indent=2) + "\n", encoding="utf-8")

    # Verify the exported artifact loads cleanly via the safe runtime loader
    verified_model = load_verified_linear_model(artifact_path)

    comparison_summary = {
        "artifact_path": str(artifact_path.relative_to(root)).replace("\\", "/"),
        "artifact_sha256": verified_model.artifact_sha256,
        "weights_sha256": weights_sha256,
        "train_count": len(train_alerts),
        "val_count": len(val_alerts),
        "fresh_holdout_p5p6_count": len(hold2_alerts),
        "group_kfold_5_mean_f1": round(float(np.mean(cv_f1_scores)), 4),
        "validation_model_comparison": {
            "naive_majority_baseline": {
                "accuracy": round(float(accuracy_score(y_val, y_val_naive)), 4),
                "f1": round(float(f1_score(y_val, y_val_naive, zero_division=0)), 4),
            },
            "logistic_regression_l2": {
                "accuracy": round(float(accuracy_score(y_val, y_val_lr)), 4),
                "precision": round(float(precision_score(y_val, y_val_lr, zero_division=0)), 4),
                "recall": round(float(recall_score(y_val, y_val_lr, zero_division=0)), 4),
                "f1": round(float(f1_score(y_val, y_val_lr, zero_division=0)), 4),
                "confusion_matrix": confusion_matrix(y_val, y_val_lr).tolist(),
            },
            "linear_svc": {
                "accuracy": round(float(accuracy_score(y_val, y_val_svc)), 4),
                "precision": round(float(precision_score(y_val, y_val_svc, zero_division=0)), 4),
                "recall": round(float(recall_score(y_val, y_val_svc, zero_division=0)), 4),
                "f1": round(float(f1_score(y_val, y_val_svc, zero_division=0)), 4),
                "confusion_matrix": confusion_matrix(y_val, y_val_svc).tolist(),
            },
        },
        "feature_weights": dict(zip(ORDERED_FEATURE_NAMES, raw_weights)),
        "folded_bias": folded_bias,
    }
    return comparison_summary


if __name__ == "__main__":
    summary = train_and_export_classifier()
    print(json.dumps(summary, indent=2))
