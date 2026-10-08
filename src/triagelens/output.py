"""Safe output staging, atomic batch finalization, partial-run reporting, and log minimization (P1-03, P1-04, P3-01)."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
from typing import Any
import uuid

from triagelens.config import (
    APPLICATION_VERSION,
    EXPLAIN_VERSION,
    NORMALIZER_VERSION,
    POLICY_VERSION,
    RESULT_SCHEMA_VERSION,
    RULESET_REVIEW_STATUS,
    SCHEMA_VERSION,
    RunConfig,
)
from triagelens.contracts import AlertResultRecord
from triagelens.explain import sanitize_for_display
from triagelens.rules import get_ruleset_sha256


class OutputDestinationError(RuntimeError):
    """Raised when the output path violates overwrite or filesystem safety rules."""


def format_safe_diagnostic(run_id: str, category: str, detail: str) -> str:
    """Format a bounded stderr diagnostic message with control characters escaped and no raw alert data."""
    safe_run = sanitize_for_display(run_id)[:64]
    safe_cat = sanitize_for_display(category)[:64]
    safe_detail = sanitize_for_display(detail)[:240]
    return f"[triagelens] run_id={safe_run} category={safe_cat} detail={safe_detail}"


class StagingRunWriter:
    """Manages staged result writing and atomic finalization so interrupted runs never claim complete."""

    def __init__(
        self,
        output_dir: str | Path,
        run_id: str,
        config: RunConfig,
        input_logical_name: str,
    ) -> None:
        self.target_dir = Path(output_dir).resolve()
        self.run_id = run_id
        self.config = config
        self.input_logical_name = sanitize_for_display(Path(input_logical_name).name)
        self.staging_dir = self.target_dir.parent / (
            f".{self.target_dir.name}.staging.{os.getpid()}.{uuid.uuid4().hex[:8]}"
        )
        self._results_fh: Any = None
        self.started_at_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Counters
        self.total_lines = 0
        self.accepted_count = 0
        self.invalid_count = 0
        self.failed_count = 0
        self.baseline_dispositions: Counter[str] = Counter()
        self.final_dispositions: Counter[str] = Counter()
        self.review_reasons: Counter[str] = Counter()
        self.error_codes: Counter[str] = Counter()
        self.classifier_states: Counter[str] = Counter()
        self.summary_sources: Counter[str] = Counter()
        self.summary_validation_states: Counter[str] = Counter()

    def open(self) -> None:
        """Validate target destination, create staging directory, and write initial partial manifest."""
        if self.target_dir.exists():
            if self.target_dir.is_symlink():
                raise OutputDestinationError("Refusing to write to a symbolic link output destination")
            if not self.config.overwrite:
                raise OutputDestinationError(
                    f"Output directory already exists ({self.target_dir.name}); pass --overwrite to replace"
                )

        parent = self.target_dir.parent
        parent.mkdir(parents=True, exist_ok=True)
        self.staging_dir.mkdir(parents=False, exist_ok=False)

        results_path = self.staging_dir / "results.jsonl"
        self._results_fh = open(results_path, "w", encoding="utf-8", newline="\n")
        # Write an immediate partial report so an abrupt crash cannot masquerade as complete
        self._write_report_file(
            completion_state="partial",
            input_sha256=None,
            failure_reason="run_in_progress",
        )

    def write_record(self, record: AlertResultRecord) -> None:
        """Write a single AlertResultRecord to the staged results.jsonl and update run counters."""
        if self._results_fh is None:
            raise RuntimeError("StagingRunWriter is not open")

        line = json.dumps(record.to_dict(), sort_keys=False, ensure_ascii=True)
        self._results_fh.write(line + "\n")

        self.total_lines += 1
        if record.processing_status == "accepted":
            self.accepted_count += 1
            if record.baseline_disposition:
                self.baseline_dispositions[record.baseline_disposition] += 1
            if record.disposition:
                self.final_dispositions[record.disposition] += 1
            for reason in record.review_reasons:
                self.review_reasons[reason] += 1
            self.classifier_states[record.optional_classifier.state] += 1
            if record.summary.source:
                self.summary_sources[record.summary.source] += 1
            self.summary_validation_states[record.summary.validation_state] += 1
        elif record.processing_status == "invalid":
            self.invalid_count += 1
            for err in record.errors:
                self.error_codes[err.code] += 1
        else:
            self.failed_count += 1
            for err in record.errors:
                self.error_codes[err.code] += 1

    def _build_report_dict(
        self,
        completion_state: str,
        input_sha256: str | None,
        failure_reason: str | None = None,
        extra_metrics: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        finished_at_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        report: dict[str, Any] = {
            "report_schema_version": RESULT_SCHEMA_VERSION,
            "run_id": self.run_id,
            "completion_state": completion_state,  # complete | partial
            "failure_reason": failure_reason,
            "started_at_utc": self.started_at_utc,
            "finished_at_utc": finished_at_utc,
            "provenance": {
                "input_logical_name": self.input_logical_name,
                "input_sha256": input_sha256,
                "application_version": APPLICATION_VERSION,
                "schema_version": SCHEMA_VERSION,
                "result_schema_version": RESULT_SCHEMA_VERSION,
                "normalizer_version": NORMALIZER_VERSION,
                "ruleset_id": self.config.ruleset_id,
                "ruleset_sha256": get_ruleset_sha256(self.config.ruleset_id),
                "ruleset_review_status": RULESET_REVIEW_STATUS,
                "policy_version": POLICY_VERSION,
                "explain_version": EXPLAIN_VERSION,
                "config_sha256": self.config.config_sha256(),
                "optional_mode": self.config.optional_mode,
                "enable_classifier": self.config.enable_classifier,
                "enable_summarizer": self.config.enable_summarizer,
            },
            "counts": {
                "total_lines": self.total_lines,
                "accepted": self.accepted_count,
                "invalid": self.invalid_count,
                "failed": self.failed_count,
            },
            "baseline_dispositions": {
                "suspicious": self.baseline_dispositions.get("suspicious", 0),
                "likely_benign": self.baseline_dispositions.get("likely_benign", 0),
                "needs_review": self.baseline_dispositions.get("needs_review", 0),
            },
            "dispositions": {
                "suspicious": self.final_dispositions.get("suspicious", 0),
                "likely_benign": self.final_dispositions.get("likely_benign", 0),
                "needs_review": self.final_dispositions.get("needs_review", 0),
            },
            "review_reasons": dict(sorted(self.review_reasons.items())),
            "error_codes": dict(sorted(self.error_codes.items())),
            "optional_components": {
                "classifier_states": dict(sorted(self.classifier_states.items())),
                "summary_sources": dict(sorted(self.summary_sources.items())),
                "summary_validation_states": dict(sorted(self.summary_validation_states.items())),
            },
        }
        if extra_metrics:
            report["runtime_metrics"] = extra_metrics
        return report

    def _write_report_file(
        self,
        completion_state: str,
        input_sha256: str | None,
        failure_reason: str | None = None,
        extra_metrics: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        report = self._build_report_dict(
            completion_state=completion_state,
            input_sha256=input_sha256,
            failure_reason=failure_reason,
            extra_metrics=extra_metrics,
        )
        report_path = self.staging_dir / "run_report.json"
        with open(report_path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=True)
            fh.write("\n")
        return report

    def finalize_complete(
        self,
        input_sha256: str,
        extra_metrics: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Flush results, write complete run_report.json, and promote staging dir to target_dir."""
        if self._results_fh is not None:
            self._results_fh.flush()
            os.fsync(self._results_fh.fileno())
            self._results_fh.close()
            self._results_fh = None

        report = self._write_report_file(
            completion_state="complete",
            input_sha256=input_sha256,
            failure_reason=None,
            extra_metrics=extra_metrics,
        )

        if self.target_dir.exists():
            if not self.config.overwrite:
                raise OutputDestinationError("Target directory appeared during run and overwrite is false")
            shutil.rmtree(self.target_dir)

        os.replace(self.staging_dir, self.target_dir)
        return report

    def finalize_partial(
        self,
        failure_reason: str,
        input_sha256: str | None = None,
        promote_to_target: bool = True,
    ) -> dict[str, Any]:
        """Flush partial results and record completion_state='partial' on abort or interruption."""
        if self._results_fh is not None:
            try:
                self._results_fh.flush()
                self._results_fh.close()
            except OSError:
                pass
            self._results_fh = None

        report = self._write_report_file(
            completion_state="partial",
            input_sha256=input_sha256,
            failure_reason=sanitize_for_display(failure_reason)[:128],
        )

        if promote_to_target and (not self.target_dir.exists() or self.config.overwrite):
            if self.target_dir.exists() and self.config.overwrite:
                shutil.rmtree(self.target_dir)
            try:
                os.replace(self.staging_dir, self.target_dir)
            except OSError:
                pass
        return report
