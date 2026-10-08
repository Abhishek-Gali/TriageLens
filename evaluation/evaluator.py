"""Reproducible evaluator, slice analyzer, and release gate verifier for TriageLens (P4-03, P4-04, P4-05)."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import socket
import tempfile
from typing import Any
from unittest.mock import patch

from triagelens.cli import run_batch
from triagelens.config import RunConfig
from triagelens.contracts import FORBIDDEN_LEAKAGE_KEYS


class _DeniedNetworkSocket(socket.socket):
    """Enforces runtime network egress denial during all evaluation runs (INV-01, G-03)."""

    def __init__(self, *args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        raise RuntimeError("Runtime network egress attempted during offline evaluation (INV-01)")


def _rate_and_counts(num: int, den: int) -> dict[str, Any]:
    if den == 0:
        return {"numerator": num, "denominator": 0, "rate": "not_applicable", "percentage": "not_applicable"}
    rate = num / den
    return {
        "numerator": num,
        "denominator": den,
        "rate": round(rate, 6),
        "percentage": f"{rate * 100.0:.2f}%",
    }


def audit_runtime_and_split_leakage(project_root: Path) -> dict[str, Any]:
    """Audit runtime code imports and split files for label/group leakage (P4-03, INV-08)."""
    import ast

    src_dir = project_root / "src" / "triagelens"
    runtime_imports_evaluation = False
    for py_file in src_dir.rglob("*.py"):
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith(("evaluation", "tests")):
                        runtime_imports_evaluation = True
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module.startswith(("evaluation", "tests")):
                    runtime_imports_evaluation = True

    dev_alerts = [
        json.loads(line)
        for line in (project_root / "evaluation" / "development" / "alerts.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    dev_labels = [
        json.loads(line)
        for line in (project_root / "evaluation" / "development" / "labels.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    hold_alerts = [
        json.loads(line)
        for line in (project_root / "evaluation" / "holdout" / "alerts.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    hold_labels = [
        json.loads(line)
        for line in (project_root / "evaluation" / "holdout" / "labels.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]

    forbidden_found: list[str] = []
    for split_name, records in (("development", dev_alerts), ("holdout", hold_alerts)):
        for rec in records:
            for k in rec:
                if k in FORBIDDEN_LEAKAGE_KEYS:
                    forbidden_found.append(f"{split_name}:{rec.get('alert_id')}:{k}")

    dev_ids = {r["alert_id"] for r in dev_alerts}
    hold_ids = {r["alert_id"] for r in hold_alerts}
    dev_fams = {l["scenario_family_id"] for l in dev_labels}
    hold_fams = {l["scenario_family_id"] for l in hold_labels}
    dev_lins = {l["template_lineage"] for l in dev_labels}
    hold_lins = {l["template_lineage"] for l in hold_labels}

    passed = (
        not runtime_imports_evaluation
        and not forbidden_found
        and len(dev_ids & hold_ids) == 0
        and len(dev_fams & hold_fams) == 0
        and len(dev_lins & hold_lins) == 0
    )
    return {
        "status": "passed" if passed else "failed",
        "runtime_imports_evaluation": runtime_imports_evaluation,
        "forbidden_keys_in_inference_records": forbidden_found,
        "dev_alert_count": len(dev_alerts),
        "holdout_alert_count": len(hold_alerts),
        "alert_id_overlap_count": len(dev_ids & hold_ids),
        "scenario_family_overlap_count": len(dev_fams & hold_fams),
        "template_lineage_overlap_count": len(dev_lins & hold_lins),
    }


def compute_metrics_for_population(
    joined_records: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compute EVALUATION.md metrics, raw counts, and 3x3 confusion matrix for a population."""
    dispositions = ("suspicious", "likely_benign", "needs_review")
    confusion: dict[str, dict[str, int]] = {
        exp: {pred: 0 for pred in (*dispositions, "invalid_or_failed")} for exp in dispositions
    }

    total_eligible = len(joined_records)
    accepted_count = 0
    invalid_or_failed_count = 0
    review_reasons_counter: Counter[str] = Counter()

    for item in joined_records:
        exp = item["label"]["expected_disposition"]
        res = item["result"]
        status = res["processing_status"]
        pred = res["disposition"]
        if status == "accepted" and pred in dispositions:
            accepted_count += 1
            confusion[exp][pred] += 1
            for r in res.get("review_reasons", []):
                review_reasons_counter[r] += 1
        else:
            invalid_or_failed_count += 1
            confusion[exp]["invalid_or_failed"] += 1

    tp_susp = confusion["suspicious"]["suspicious"]
    pred_susp = sum(confusion[exp]["suspicious"] for exp in dispositions)
    exp_susp = sum(confusion["suspicious"].values())

    exp_susp_pred_benign = confusion["suspicious"]["likely_benign"]

    pred_benign = sum(confusion[exp]["likely_benign"] for exp in dispositions)
    total_decisive = pred_susp + pred_benign
    correct_decisive = confusion["suspicious"]["suspicious"] + confusion["likely_benign"]["likely_benign"]
    incorrect_decisive = total_decisive - correct_decisive

    pred_review = sum(confusion[exp]["needs_review"] for exp in dispositions)

    return {
        "eligible_population": total_eligible,
        "accepted_count": accepted_count,
        "invalid_or_failed_count": invalid_or_failed_count,
        "confusion_matrix": confusion,
        "metrics": {
            "suspicious_precision": _rate_and_counts(tp_susp, pred_susp),
            "suspicious_recall": _rate_and_counts(tp_susp, exp_susp),
            "critical_benign_miss_rate": _rate_and_counts(exp_susp_pred_benign, exp_susp),
            "decisive_coverage": _rate_and_counts(total_decisive, total_eligible),
            "selective_error": _rate_and_counts(incorrect_decisive, total_decisive),
            "review_rate": _rate_and_counts(pred_review, total_eligible),
            "processing_success": _rate_and_counts(accepted_count, total_eligible),
        },
        "review_reason_distribution": dict(sorted(review_reasons_counter.items())),
    }


def evaluate_split(
    alerts_path: Path,
    labels_path: Path,
    output_dir: Path,
    config: RunConfig | None = None,
) -> dict[str, Any]:
    """Run batch triage under denied network egress and evaluate against separate labels."""
    cfg = config or RunConfig(overwrite=True)

    with (
        patch("socket.socket", _DeniedNetworkSocket),
        patch("socket.create_connection", side_effect=RuntimeError("Denied connect")),
        patch("socket.getaddrinfo", side_effect=RuntimeError("Denied DNS")),
    ):
        batch_report = run_batch(input_path=alerts_path, output_dir=output_dir, config=cfg)

    results_by_id: dict[str, dict[str, Any]] = {}
    results_list: list[dict[str, Any]] = []
    for line in (output_dir / "results.jsonl").read_text(encoding="utf-8").splitlines():
        rec = json.loads(line)
        results_list.append(rec)
        if rec.get("alert_id"):
            results_by_id[rec["alert_id"]] = rec

    labels_list = [
        json.loads(line) for line in labels_path.read_text(encoding="utf-8").splitlines()
    ]
    alerts_by_id = {
        json.loads(line)["alert_id"]: json.loads(line)
        for line in alerts_path.read_text(encoding="utf-8").splitlines()
    }

    joined: list[dict[str, Any]] = []
    disagreements: list[dict[str, Any]] = []
    for lbl in labels_list:
        aid = lbl["alert_id"]
        res = results_by_id[aid]
        alert_obj = alerts_by_id[aid]
        item = {"alert": alert_obj, "label": lbl, "result": res}
        joined.append(item)
        if res["disposition"] != lbl["expected_disposition"]:
            disagreements.append(
                {
                    "alert_id": aid,
                    "family": alert_obj["family"],
                    "event_name": alert_obj["event_name"],
                    "scenario_family_id": lbl["scenario_family_id"],
                    "underlying_scenario_state": lbl["underlying_scenario_state"],
                    "expected_disposition": lbl["expected_disposition"],
                    "predicted_disposition": res["disposition"],
                    "matched_rule_ids": res["matched_rule_ids"],
                    "review_reasons": res["review_reasons"],
                    "rationale": lbl["rationale"],
                }
            )

    overall = compute_metrics_for_population(joined)

    # Slices by family
    by_family: dict[str, Any] = {}
    for fam in ("authentication", "process", "network"):
        fam_items = [x for x in joined if x["alert"]["family"] == fam]
        by_family[fam] = compute_metrics_for_population(fam_items)

    # Slices by slice_category (standard families vs uncertainty slice)
    by_slice_category: dict[str, Any] = {}
    for cat in ("authentication", "process", "network", "uncertainty"):
        cat_items = [x for x in joined if x["label"]["slice_category"] == cat]
        by_slice_category[cat] = compute_metrics_for_population(cat_items)

    # Slices by scenario_family_id
    by_scenario_family: dict[str, Any] = {}
    scen_ids = sorted({x["label"]["scenario_family_id"] for x in joined})
    for sid in scen_ids:
        s_items = [x for x in joined if x["label"]["scenario_family_id"] == sid]
        by_scenario_family[sid] = compute_metrics_for_population(s_items)

    return {
        "batch_report": batch_report,
        "overall": overall,
        "slices": {
            "by_family": by_family,
            "by_slice_category": by_slice_category,
            "by_scenario_family": by_scenario_family,
        },
        "disagreements": disagreements,
    }


def run_three_run_determinism_and_resource_probe(
    alerts_path: Path,
) -> dict[str, Any]:
    """Execute 3 repeated runs on the given split to measure determinism and resource metrics (P3-04, G-04)."""
    run_metrics: list[dict[str, Any]] = []
    semantic_outputs: list[list[dict[str, Any]]] = []

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        for i in range(3):
            out_dir = tmp_path / f"det_run_{i}"
            with (
                patch("socket.socket", _DeniedNetworkSocket),
                patch("socket.create_connection", side_effect=RuntimeError("Denied connect")),
                patch("socket.getaddrinfo", side_effect=RuntimeError("Denied DNS")),
            ):
                rep = run_batch(input_path=alerts_path, output_dir=out_dir)

            run_metrics.append(rep["runtime_metrics"])
            records = []
            for line in (out_dir / "results.jsonl").read_text(encoding="utf-8").splitlines():
                obj = json.loads(line)
                del obj["run_id"]
                del obj["timing"]
                records.append(obj)
            semantic_outputs.append(records)

    identical = (semantic_outputs[0] == semantic_outputs[1]) and (
        semantic_outputs[1] == semantic_outputs[2]
    )
    wall_times = [m["batch_wall_ms"] for m in run_metrics]
    p99_times = [m["p99_record_ms"] for m in run_metrics]
    peaks_mib = [m["peak_traced_memory_mib"] for m in run_metrics]

    return {
        "three_runs_semantically_identical": identical,
        "runs": run_metrics,
        "summary": {
            "min_batch_wall_ms": min(wall_times),
            "max_batch_wall_ms": max(wall_times),
            "max_p99_record_ms": max(p99_times),
            "max_peak_traced_memory_mib": max(peaks_mib),
        },
    }
