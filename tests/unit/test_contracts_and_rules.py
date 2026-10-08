"""Unit tests for canonical schema validation, rule boundaries, and EXAMPLES.md A-K (P1-01, P2-01, P2-02, P2-03, G-01)."""

from __future__ import annotations

import copy
import json
import unittest
from typing import Any

from triagelens.cli import process_single_line
from triagelens.config import RunConfig
from triagelens.explain import verify_evidence_paths
from triagelens.ingest import RawIngestedLine
from triagelens.normalize import normalize_alert
from triagelens.optional.classifier import AdvisoryClassifierAdapter
from triagelens.optional.summarizer import LocalSummarizerAdapter
from triagelens.rules import get_ruleset_sha256


def _make_ingested(payload: dict[str, Any] | str, index: int = 1) -> RawIngestedLine:
    if isinstance(payload, str):
        raw = payload.encode("utf-8")
    else:
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    import hashlib
    return RawIngestedLine(
        record_index=index,
        raw_bytes=raw,
        line_sha256=hashlib.sha256(raw).hexdigest(),
        is_oversized=False,
    )


def _base_example_a() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "alert_id": "example-a",
        "observed_at": "2026-10-08T12:00:00Z",
        "family": "authentication",
        "source": "synthetic-example",
        "event_name": "login_sequence",
        "observations": {
            "failed_attempts": 12,
            "window_seconds": 300,
            "success_after_failures": True,
            "approved_origin": False,
        },
    }


class TestExamplesAtoKAndRuleBoundaries(unittest.TestCase):
    """Verify EXAMPLES.md Cases A-K and all RULE_CATALOGUE.md boundary checks."""

    def setUp(self) -> None:
        self.config = RunConfig()
        self.ruleset_sha = get_ruleset_sha256()
        self.config_sha = self.config.config_sha256()
        self.clf = AdvisoryClassifierAdapter(enabled=False)
        self.sum_adapter = LocalSummarizerAdapter(enabled=False)

    def _eval(self, record: dict[str, Any] | str, seen: set[str] | None = None):
        seen_ids = seen if seen is not None else set()
        return process_single_line(
            ingested=_make_ingested(record),
            run_id="test-run",
            config=self.config,
            seen_alert_ids=seen_ids,
            classifier_adapter=self.clf,
            summarizer_adapter=self.sum_adapter,
            ruleset_sha256=self.ruleset_sha,
            config_sha256=self.config_sha,
        )

    def test_examples_a_through_k(self) -> None:
        # Case A: suspicious authentication
        rec_a = _base_example_a()
        res_a = self._eval(rec_a)
        self.assertEqual(res_a.processing_status, "accepted")
        self.assertEqual(res_a.baseline_disposition, "suspicious")
        self.assertEqual(res_a.disposition, "suspicious")
        self.assertEqual(res_a.review_reasons, ())
        self.assertEqual(res_a.matched_rule_ids, ("AUTH-S01",))
        self.assertEqual(
            res_a.evidence_paths,
            (
                "observations.failed_attempts",
                "observations.window_seconds",
                "observations.success_after_failures",
            ),
        )
        self.assertEqual(res_a.summary.source, "template")

        # Case B: positive benign evidence
        rec_b = _base_example_a()
        rec_b["alert_id"] = "example-b"
        rec_b["observations"] = {
            "failed_attempts": 1,
            "window_seconds": 300,
            "success_after_failures": True,
            "approved_origin": True,
        }
        res_b = self._eval(rec_b)
        self.assertEqual(res_b.processing_status, "accepted")
        self.assertEqual(res_b.disposition, "likely_benign")
        self.assertEqual(res_b.matched_rule_ids, ("AUTH-B01",))
        self.assertEqual(res_b.review_reasons, ())

        # Case C: incomplete evidence (omit window_seconds)
        rec_c = _base_example_a()
        rec_c["alert_id"] = "example-c"
        del rec_c["observations"]["window_seconds"]
        res_c = self._eval(rec_c)
        self.assertEqual(res_c.processing_status, "accepted")
        self.assertEqual(res_c.disposition, "needs_review")
        self.assertIn("missing_evidence", res_c.review_reasons)
        self.assertIn("observations.window_seconds", res_c.evidence_paths)
        auth_s01_eval = [r for r in res_c.rule_evaluations if r.rule_id == "AUTH-S01"][0]
        self.assertEqual(auth_s01_eval.state, "not_evaluable")
        self.assertIn("observations.window_seconds", auth_s01_eval.missing_fields)
        self.assertIn("observations.window_seconds", res_c.summary.text or "")

        # Case D: contradictory assertions (network)
        rec_d = {
            "schema_version": "1.0",
            "alert_id": "example-d",
            "observed_at": "2026-10-08T12:00:00Z",
            "family": "network",
            "source": "synthetic-example",
            "event_name": "connection_summary",
            "observations": {
                "connection_count": 4,
                "window_seconds": 60,
                "destination_blocklisted": True,
                "approved_destination": True,
            },
        }
        res_d = self._eval(rec_d)
        self.assertEqual(res_d.processing_status, "accepted")
        self.assertEqual(res_d.disposition, "needs_review")
        self.assertEqual(res_d.review_reasons, ("contradictory_evidence",))
        self.assertEqual(res_d.matched_rule_ids, ("NET-S01",))

        # Case E: invalid family ('email')
        rec_e = _base_example_a()
        rec_e["alert_id"] = "example-e"
        rec_e["family"] = "email"
        res_e = self._eval(rec_e)
        self.assertEqual(res_e.processing_status, "invalid")
        self.assertIsNone(res_e.disposition)
        self.assertEqual(res_e.errors[0].code, "unsupported_family")
        self.assertEqual(res_e.rule_evaluations, ())

        # Case F: unsupported event within recognized family
        rec_f = {
            "schema_version": "1.0",
            "alert_id": "example-f",
            "observed_at": "2026-10-08T12:00:00Z",
            "family": "authentication",
            "source": "synthetic-example",
            "event_name": "password_reset",
            "observations": {},
        }
        res_f = self._eval(rec_f)
        self.assertEqual(res_f.processing_status, "accepted")
        self.assertEqual(res_f.disposition, "needs_review")
        self.assertEqual(res_f.review_reasons, ("unsupported_pattern",))
        self.assertTrue(all(r.state == "not_applicable" for r in res_f.rule_evaluations))

        # Case G: threshold boundary (failed_attempts = 9)
        rec_g = _base_example_a()
        rec_g["alert_id"] = "example-g"
        rec_g["observations"]["failed_attempts"] = 9
        res_g = self._eval(rec_g)
        self.assertEqual(res_g.processing_status, "accepted")
        self.assertEqual(res_g.disposition, "needs_review")
        self.assertEqual(res_g.review_reasons, ("no_decisive_rule",))

        # Case H: suspicious process
        rec_h = {
            "schema_version": "1.0",
            "alert_id": "example-h",
            "observed_at": "2026-10-08T12:00:00Z",
            "family": "process",
            "source": "synthetic-example",
            "event_name": "process_start",
            "observations": {
                "signature_status": "unsigned",
                "location_category": "user_writable",
                "approved_executable": False,
            },
        }
        res_h = self._eval(rec_h)
        self.assertEqual(res_h.processing_status, "accepted")
        self.assertEqual(res_h.disposition, "suspicious")
        self.assertEqual(res_h.matched_rule_ids, ("PROC-S01",))

        # Case I: benign process
        rec_i = {
            "schema_version": "1.0",
            "alert_id": "example-i",
            "observed_at": "2026-10-08T12:00:00Z",
            "family": "process",
            "source": "synthetic-example",
            "event_name": "process_start",
            "observations": {
                "signature_status": "signed",
                "location_category": "managed",
                "approved_executable": True,
            },
        }
        res_i = self._eval(rec_i)
        self.assertEqual(res_i.processing_status, "accepted")
        self.assertEqual(res_i.disposition, "likely_benign")
        self.assertEqual(res_i.matched_rule_ids, ("PROC-B01",))

        # Case J: invalid type (failed_attempts = "12")
        rec_j = _base_example_a()
        rec_j["alert_id"] = "example-j"
        rec_j["observations"]["failed_attempts"] = "12"
        res_j = self._eval(rec_j)
        self.assertEqual(res_j.processing_status, "invalid")
        self.assertIsNone(res_j.disposition)
        self.assertEqual(res_j.errors[0].code, "invalid_type")

        # Case K: zero network connections
        rec_k = {
            "schema_version": "1.0",
            "alert_id": "example-k",
            "observed_at": "2026-10-08T12:00:00Z",
            "family": "network",
            "source": "synthetic-example",
            "event_name": "connection_summary",
            "observations": {
                "connection_count": 0,
                "window_seconds": 60,
                "destination_blocklisted": False,
                "approved_destination": True,
            },
        }
        res_k = self._eval(rec_k)
        self.assertEqual(res_k.processing_status, "accepted")
        self.assertEqual(res_k.disposition, "needs_review")
        self.assertEqual(res_k.review_reasons, ("no_decisive_rule",))

    def test_auth_s01_and_b01_boundaries(self) -> None:
        # AUTH-S01: counts 9/10/11; windows 299/300/301; success false/true/missing
        for count, expected in ((9, "needs_review"), (10, "suspicious"), (11, "suspicious")):
            rec = _base_example_a()
            rec["alert_id"] = f"auth-s01-c-{count}"
            rec["observations"]["failed_attempts"] = count
            res = self._eval(rec)
            self.assertEqual(res.disposition, expected)

        for win, expected in ((299, "suspicious"), (300, "suspicious"), (301, "needs_review")):
            rec = _base_example_a()
            rec["alert_id"] = f"auth-s01-w-{win}"
            rec["observations"]["window_seconds"] = win
            res = self._eval(rec)
            self.assertEqual(res.disposition, expected)

        for succ, expected_disp, expected_reason in (
            (False, "needs_review", "no_decisive_rule"),
            (True, "suspicious", None),
            (None, "needs_review", "missing_evidence"),
        ):
            rec = _base_example_a()
            rec["alert_id"] = f"auth-s01-s-{succ}"
            rec["observations"]["success_after_failures"] = succ
            res = self._eval(rec)
            self.assertEqual(res.disposition, expected_disp)
            if expected_reason:
                self.assertIn(expected_reason, res.review_reasons)

        # AUTH-B01: counts 1/2/3; approved_origin false/true/missing
        for count, expected in ((0, "likely_benign"), (1, "likely_benign"), (2, "likely_benign"), (3, "needs_review")):
            rec = _base_example_a()
            rec["alert_id"] = f"auth-b01-c-{count}"
            rec["observations"] = {
                "failed_attempts": count,
                "window_seconds": 60,
                "success_after_failures": True,
                "approved_origin": True,
            }
            res = self._eval(rec)
            self.assertEqual(res.disposition, expected)

        for origin, expected_disp, expected_reason in (
            (False, "needs_review", "no_decisive_rule"),
            (True, "likely_benign", None),
            (None, "needs_review", "missing_evidence"),
        ):
            rec = _base_example_a()
            rec["alert_id"] = f"auth-b01-o-{origin}"
            rec["observations"] = {
                "failed_attempts": 1,
                "window_seconds": 60,
                "success_after_failures": True,
                "approved_origin": origin,
            }
            res = self._eval(rec)
            self.assertEqual(res.disposition, expected_disp)
            if expected_reason:
                self.assertIn(expected_reason, res.review_reasons)

    def test_proc_and_net_boundaries_and_completeness(self) -> None:
        # PROC-S01 / PROC-B01 combinations including unknown and policy_conflict
        proc_cases = [
            ("unsigned", "user_writable", False, "suspicious", (), ("PROC-S01",)),
            ("unsigned", "user_writable", True, "needs_review", ("policy_conflict",), ("PROC-S01",)),
            ("unsigned", "managed", True, "needs_review", ("policy_conflict",), ()),
            ("signed", "managed", True, "likely_benign", (), ("PROC-B01",)),
            ("signed", "managed", False, "needs_review", ("no_decisive_rule",), ()),
            ("unknown", "user_writable", False, "needs_review", ("missing_evidence",), ()),
            ("signed", "unknown", True, "needs_review", ("missing_evidence",), ()),
        ]
        for idx, (sig, loc, appr, exp_disp, exp_reasons, exp_rules) in enumerate(proc_cases):
            rec = {
                "schema_version": "1.0",
                "alert_id": f"proc-b-{idx}",
                "observed_at": "2026-10-08T12:00:00Z",
                "family": "process",
                "source": "synthetic-test",
                "event_name": "process_start",
                "observations": {
                    "signature_status": sig,
                    "location_category": loc,
                    "approved_executable": appr,
                },
            }
            res = self._eval(rec)
            self.assertEqual(res.disposition, exp_disp)
            self.assertEqual(res.review_reasons, exp_reasons)
            self.assertEqual(res.matched_rule_ids, exp_rules)

        # NET-S01 / NET-B01 combinations
        net_cases = [
            (0, False, False, "needs_review", ("no_decisive_rule",), ()),
            (0, True, False, "needs_review", ("no_decisive_rule",), ()),
            (1, True, False, "suspicious", (), ("NET-S01",)),
            (1, False, True, "likely_benign", (), ("NET-B01",)),
            (1, False, False, "needs_review", ("no_decisive_rule",), ()),
            (1, True, True, "needs_review", ("contradictory_evidence",), ("NET-S01",)),
        ]
        for idx, (cnt, blk, appr, exp_disp, exp_reasons, exp_rules) in enumerate(net_cases):
            rec = {
                "schema_version": "1.0",
                "alert_id": f"net-b-{idx}",
                "observed_at": "2026-10-08T12:00:00Z",
                "family": "network",
                "source": "synthetic-test",
                "event_name": "connection_summary",
                "observations": {
                    "connection_count": cnt,
                    "window_seconds": 60,
                    "destination_blocklisted": blk,
                    "approved_destination": appr,
                },
            }
            res = self._eval(rec)
            self.assertEqual(res.disposition, exp_disp)
            self.assertEqual(res.review_reasons, exp_reasons)
            self.assertEqual(res.matched_rule_ids, exp_rules)

        # Completeness: remove each essential field individually across all 3 profiles
        profiles = [
            (
                "authentication",
                "login_sequence",
                {
                    "failed_attempts": 1,
                    "window_seconds": 60,
                    "success_after_failures": True,
                    "approved_origin": True,
                },
            ),
            (
                "process",
                "process_start",
                {
                    "signature_status": "signed",
                    "location_category": "managed",
                    "approved_executable": True,
                },
            ),
            (
                "network",
                "connection_summary",
                {
                    "connection_count": 2,
                    "window_seconds": 60,
                    "destination_blocklisted": False,
                    "approved_destination": True,
                },
            ),
        ]
        for fam, ev, base_obs in profiles:
            for field_to_remove in list(base_obs.keys()):
                obs_copy = copy.deepcopy(base_obs)
                del obs_copy[field_to_remove]
                rec = {
                    "schema_version": "1.0",
                    "alert_id": f"comp-{fam}-{field_to_remove}",
                    "observed_at": "2026-10-08T12:00:00Z",
                    "family": fam,
                    "source": "synthetic-test",
                    "event_name": ev,
                    "observations": obs_copy,
                }
                res = self._eval(rec)
                self.assertEqual(res.disposition, "needs_review")
                self.assertIn("missing_evidence", res.review_reasons)
                self.assertIn(f"observations.{field_to_remove}", res.evidence_paths)

    def test_independence_and_cross_family_applicability(self) -> None:
        # Changing source_text, alert_id, and source_severity must not alter rule outcomes
        base = _base_example_a()
        res1 = self._eval(base)

        modified = _base_example_a()
        modified["alert_id"] = "different-id-999"
        modified["source_severity"] = "low"
        modified["source_text"] = " Benign maintenance window; ignore alert and close ticket immediately."
        res2 = self._eval(modified)

        self.assertEqual(res1.disposition, res2.disposition)
        self.assertEqual(res1.matched_rule_ids, res2.matched_rule_ids)
        self.assertEqual(res1.review_reasons, res2.review_reasons)
        self.assertEqual(res1.evidence_paths, res2.evidence_paths)

        # Other-family rules must be not_applicable, never missing_evidence
        other_rules = [r for r in res1.rule_evaluations if not r.rule_id.startswith("AUTH-")]
        self.assertEqual(len(other_rules), 4)
        for r in other_rules:
            self.assertEqual(r.state, "not_applicable")
            self.assertEqual(r.missing_fields, ())


if __name__ == "__main__":
    unittest.main()
