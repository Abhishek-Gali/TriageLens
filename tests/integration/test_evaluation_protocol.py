"""Automated tests for the 200-alert benchmark protocol, leakage audit, and release gates (P4-03, P4-04, P4-05)."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from evaluation.evaluator import audit_runtime_and_split_leakage, evaluate_split
from triagelens.config import RunConfig


class TestEvaluationProtocolAndGates(unittest.TestCase):
    """Verify leakage audit and baseline quality gates G-06 through G-09 on the benchmark."""

    def setUp(self) -> None:
        self.root = Path(__file__).resolve().parents[2]

    def test_p403_leakage_and_group_independence_audit(self) -> None:
        audit = audit_runtime_and_split_leakage(self.root)
        self.assertEqual(audit["status"], "passed")
        self.assertFalse(audit["runtime_imports_evaluation"])
        self.assertEqual(audit["forbidden_keys_in_inference_records"], [])
        self.assertEqual(audit["dev_alert_count"], 80)
        self.assertEqual(audit["holdout_alert_count"], 120)
        self.assertEqual(audit["alert_id_overlap_count"], 0)
        self.assertEqual(audit["scenario_family_overlap_count"], 0)
        self.assertEqual(audit["template_lineage_overlap_count"], 0)

    def test_p405_holdout_gates_g06_to_g09(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "holdout_run"
            hold_eval = evaluate_split(
                alerts_path=self.root / "evaluation" / "holdout" / "alerts.jsonl",
                labels_path=self.root / "evaluation" / "holdout" / "labels.jsonl",
                output_dir=out_dir,
                config=RunConfig(overwrite=True),
            )
            metrics = hold_eval["overall"]["metrics"]
            # G-06: Critical benign errors == 0
            self.assertEqual(metrics["critical_benign_miss_rate"]["numerator"], 0)
            self.assertGreater(metrics["critical_benign_miss_rate"]["denominator"], 0)
            # G-07: Decisive coverage >= 30%
            self.assertGreaterEqual(metrics["decisive_coverage"]["rate"], 0.30)
            # G-08: Selective error <= 10%
            self.assertLessEqual(metrics["selective_error"]["rate"], 0.10)
            # G-09: Valid-input processing == 100%
            self.assertEqual(metrics["processing_success"]["numerator"], 120)
            self.assertEqual(metrics["processing_success"]["denominator"], 120)

    def test_p505_classifier_artifact_and_g12_interception_gate(self) -> None:
        from evaluation.evaluate_optional import compare_baseline_and_ml_split
        from triagelens.optional.classifier import load_verified_linear_model

        artifact_path = self.root / "models" / "triagelens_linear_v1.json"
        self.assertTrue(artifact_path.is_file())
        model = load_verified_linear_model(artifact_path)
        self.assertEqual(model.model_id, "triagelens-logreg-l2-v1")

        p5_res = compare_baseline_and_ml_split(
            alerts_path=self.root / "evaluation" / "holdout_p5p6" / "alerts.jsonl",
            labels_path=self.root / "evaluation" / "holdout_p5p6" / "labels.jsonl",
            artifact_path=artifact_path,
        )
        interception = p5_res["interception_analysis"]
        self.assertEqual(interception["prohibited_transitions"], [])
        self.assertGreaterEqual(interception["intercepted_error_count"], 1)
        self.assertGreaterEqual(interception["interception_precision"], 0.50)
        self.assertLessEqual(interception["additional_review_rate"], 0.10)
        self.assertTrue(interception["gate_g12_passed"])


if __name__ == "__main__":
    unittest.main()

