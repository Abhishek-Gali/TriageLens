"""Batch CLI and pipeline orchestrator for TriageLens (P2-04, P3-01, P3-02, P3-04, P5-04, P6-03)."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
import time
import tracemalloc
from typing import Any, Callable
import uuid

from triagelens.config import (
    APPLICATION_VERSION,
    DEFAULT_CLASSIFIER_ARTIFACT,
    DEFAULT_SUMMARIZER_ENDPOINT,
    DEFAULT_SUMMARIZER_MODEL,
    NORMALIZER_VERSION,
    POLICY_VERSION,
    RESULT_SCHEMA_VERSION,
    RULESET_ID,
    RULESET_REVIEW_STATUS,
    SCHEMA_VERSION,
    ConfigurationError,
    RunConfig,
)
from triagelens.contracts import (
    AlertResultRecord,
    ClassifierOutput,
    ProvenanceRecord,
    SummaryRecord,
    TimingRecord,
    ValidationErrorRecord,
    validate_raw_record,
)
from triagelens.explain import verify_evidence_paths
from triagelens.ingest import BoundedJsonlReader, IngestionLimitError, RawIngestedLine
from triagelens.normalize import normalize_alert
from triagelens.optional.classifier import (
    AdvisoryClassifierAdapter,
    UnsafeModelArtifactError,
    load_verified_linear_model,
)
from triagelens.optional.summarizer import (
    LocalSummarizerAdapter,
    RestrictedEvidencePacket,
    make_ollama_loopback_generator,
    verify_ollama_loopback_model,
)
from triagelens.output import OutputDestinationError, StagingRunWriter, format_safe_diagnostic
from triagelens.policy import apply_decision_policy
from triagelens.rules import evaluate_rules, get_ruleset_sha256


def _build_provenance(
    line_sha256: str,
    config: RunConfig,
    ruleset_sha256: str,
    config_sha256: str,
) -> ProvenanceRecord:
    return ProvenanceRecord(
        input_record_sha256=line_sha256,
        schema_version=SCHEMA_VERSION,
        result_schema_version=RESULT_SCHEMA_VERSION,
        normalizer_version=NORMALIZER_VERSION,
        ruleset_id=config.ruleset_id,
        ruleset_sha256=ruleset_sha256,
        ruleset_review_status=RULESET_REVIEW_STATUS,
        policy_version=POLICY_VERSION,
        application_version=APPLICATION_VERSION,
        config_sha256=config_sha256,
    )


def process_single_line(
    ingested: RawIngestedLine,
    run_id: str,
    config: RunConfig,
    seen_alert_ids: set[str],
    classifier_adapter: AdvisoryClassifierAdapter,
    summarizer_adapter: LocalSummarizerAdapter,
    ruleset_sha256: str,
    config_sha256: str,
) -> AlertResultRecord:
    """Process one raw JSONL line through validation, normalization, rules, policy, and explanation."""
    t0_ns = time.monotonic_ns()
    provenance = _build_provenance(
        line_sha256=ingested.line_sha256,
        config=config,
        ruleset_sha256=ruleset_sha256,
        config_sha256=config_sha256,
    )

    canonical, errors = validate_raw_record(
        raw_bytes=ingested.raw_bytes,
        is_oversized=ingested.is_oversized,
        config=config,
        seen_alert_ids=seen_alert_ids,
    )

    if canonical is None or errors:
        total_ns = max(1, time.monotonic_ns() - t0_ns)
        return AlertResultRecord(
            run_id=run_id,
            record_index=ingested.record_index,
            alert_id=None,
            processing_status="invalid",
            errors=tuple(errors),
            baseline_disposition=None,
            disposition=None,
            review_reasons=(),
            matched_rule_ids=(),
            evidence_paths=(),
            rule_evaluations=(),
            provenance=provenance,
            optional_classifier=ClassifierOutput(
                state="disabled" if not config.enable_classifier else "unavailable"
            ),
            summary=SummaryRecord(
                text=None,
                source=None,
                template_text=None,
                validation_state="not_applicable",
                fallback_reason=None,
            ),
            timing=TimingRecord(
                total_ns=total_ns,
                baseline_ns=total_ns,
                classifier_ns=0,
                summarizer_ns=0,
            ),
        )

    try:
        normalized = normalize_alert(canonical)
        rule_evals = evaluate_rules(normalized, ruleset_id=config.ruleset_id)
        t_after_rules_ns = time.monotonic_ns()

        # Optional classifier evaluation
        t_clf_start_ns = time.monotonic_ns()
        clf_output = classifier_adapter.evaluate(normalized)
        t_clf_end_ns = time.monotonic_ns()
        classifier_ns = max(0, t_clf_end_ns - t_clf_start_ns) if config.enable_classifier else 0

        # Deterministic policy owns baseline_disposition and final disposition (INV-03)
        t_pol_start_ns = time.monotonic_ns()
        decision = apply_decision_policy(
            alert=normalized,
            rule_evaluations=rule_evals,
            classifier_output=clf_output if config.enable_classifier else None,
        )
        unresolved = verify_evidence_paths(normalized, decision)
        if unresolved:
            raise RuntimeError(f"Unresolved evidence paths: {', '.join(unresolved)}")
        t_pol_end_ns = time.monotonic_ns()

        # Summary rendering & optional LLM enrichment after decision is frozen (INV-04)
        t_sum_start_ns = time.monotonic_ns()
        summary_record = summarizer_adapter.summarize(normalized, decision)
        t_sum_end_ns = time.monotonic_ns()

        if config.enable_summarizer:
            summarizer_ns = max(0, t_sum_end_ns - t_sum_start_ns)
            baseline_ns = max(1, (t_after_rules_ns - t0_ns) + (t_pol_end_ns - t_pol_start_ns))
        else:
            summarizer_ns = 0
            baseline_ns = max(1, (t_after_rules_ns - t0_ns) + (t_sum_end_ns - t_pol_start_ns))

        total_ns = max(1, time.monotonic_ns() - t0_ns)
        return AlertResultRecord(
            run_id=run_id,
            record_index=ingested.record_index,
            alert_id=normalized.alert_id,
            processing_status="accepted",
            errors=(),
            baseline_disposition=decision.baseline_disposition,
            disposition=decision.disposition,
            review_reasons=decision.review_reasons,
            matched_rule_ids=decision.matched_rule_ids,
            evidence_paths=decision.evidence_paths,
            rule_evaluations=decision.rule_evaluations,
            provenance=provenance,
            optional_classifier=clf_output,
            summary=summary_record,
            timing=TimingRecord(
                total_ns=total_ns,
                baseline_ns=baseline_ns,
                classifier_ns=classifier_ns,
                summarizer_ns=summarizer_ns,
            ),
        )
    except Exception:
        total_ns = max(1, time.monotonic_ns() - t0_ns)
        return AlertResultRecord(
            run_id=run_id,
            record_index=ingested.record_index,
            alert_id=canonical.alert_id,
            processing_status="failed",
            errors=(
                ValidationErrorRecord(
                    code="internal_processing_failure",
                    message="Processing could not finish for record",
                    field=None,
                ),
            ),
            baseline_disposition=None,
            disposition=None,
            review_reasons=(),
            matched_rule_ids=(),
            evidence_paths=(),
            rule_evaluations=(),
            provenance=provenance,
            optional_classifier=ClassifierOutput(
                state="disabled" if not config.enable_classifier else "failed"
            ),
            summary=SummaryRecord(
                text=None,
                source=None,
                template_text=None,
                validation_state="not_applicable",
                fallback_reason="record_processing_failed",
            ),
            timing=TimingRecord(
                total_ns=total_ns,
                baseline_ns=total_ns,
                classifier_ns=0,
                summarizer_ns=0,
            ),
        )


def _init_optional_components(
    config: RunConfig,
    custom_summarizer_fn: Callable[[RestrictedEvidencePacket], Any] | None = None,
) -> tuple[AdvisoryClassifierAdapter, LocalSummarizerAdapter]:
    """Initialize optional classifier and summarizer according to permissive vs. strict startup mode."""
    # 1. Classifier
    if not config.enable_classifier:
        clf_adapter = AdvisoryClassifierAdapter(enabled=False)
    else:
        artifact_path = config.classifier_artifact_path
        if not artifact_path:
            # Check if the default artifact exists in workspace
            default_candidate = Path(DEFAULT_CLASSIFIER_ARTIFACT)
            if default_candidate.exists():
                artifact_path = str(default_candidate)

        if not artifact_path:
            if config.optional_mode == "strict":
                raise ConfigurationError(
                    "Classifier enabled in strict mode, but no classifier_artifact_path was provided or found"
                )
            clf_adapter = AdvisoryClassifierAdapter(
                enabled=True,
                model=None,
                timeout_ms=config.classifier_timeout_ms,
                unavailable_reason="missing_classifier_artifact_path",
            )
        else:
            try:
                model = load_verified_linear_model(artifact_path)
                clf_adapter = AdvisoryClassifierAdapter(
                    enabled=True,
                    model=model,
                    timeout_ms=config.classifier_timeout_ms,
                )
            except (UnsafeModelArtifactError, FileNotFoundError, OSError) as exc:
                if isinstance(exc, UnsafeModelArtifactError):
                    # Unsafe model format / schema mismatch is always rejected (SECURITY.md, G-11)
                    raise
                if config.optional_mode == "strict":
                    raise ConfigurationError(
                        "Classifier enabled in strict mode, but classifier artifact was not found"
                    ) from exc
                clf_adapter = AdvisoryClassifierAdapter(
                    enabled=True,
                    model=None,
                    timeout_ms=config.classifier_timeout_ms,
                    unavailable_reason="classifier_artifact_not_found",
                )

    # 2. Summarizer
    if not config.enable_summarizer:
        sum_adapter = LocalSummarizerAdapter(enabled=False)
    else:
        if custom_summarizer_fn is not None:
            sum_adapter = LocalSummarizerAdapter(
                enabled=True,
                generator_fn=custom_summarizer_fn,
                model_id=config.summarizer_model,
            )
        elif config.summarizer_endpoint is not None:
            ok, reason = verify_ollama_loopback_model(
                endpoint=config.summarizer_endpoint,
                model=config.summarizer_model,
            )
            if not ok:
                if config.optional_mode == "strict":
                    raise ConfigurationError(
                        f"Summarizer enabled in strict mode, but local loopback endpoint is unavailable ({reason})"
                    )
                sum_adapter = LocalSummarizerAdapter(
                    enabled=True,
                    generator_fn=None,
                    unavailable_reason=reason or "local_llm_unavailable",
                    model_id=config.summarizer_model,
                )
            else:
                gen_fn = make_ollama_loopback_generator(
                    endpoint=config.summarizer_endpoint,
                    model=config.summarizer_model,
                    timeout_ms=config.summarizer_timeout_ms,
                )
                sum_adapter = LocalSummarizerAdapter(
                    enabled=True,
                    generator_fn=gen_fn,
                    model_id=config.summarizer_model,
                )
        else:
            if config.optional_mode == "strict":
                raise ConfigurationError(
                    "Summarizer enabled in strict mode, but no local loopback endpoint was configured"
                )
            sum_adapter = LocalSummarizerAdapter(
                enabled=True,
                generator_fn=None,
                unavailable_reason="local_llm_unavailable",
                model_id=config.summarizer_model,
            )

    return clf_adapter, sum_adapter


def _percentile(sorted_vals: list[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = int(round((pct / 100.0) * (len(sorted_vals) - 1)))
    idx = max(0, min(len(sorted_vals) - 1, idx))
    return sorted_vals[idx]


def run_batch(
    input_path: str | Path,
    output_dir: str | Path,
    config: RunConfig | None = None,
    run_id: str | None = None,
    custom_summarizer_fn: Callable[[RestrictedEvidencePacket], Any] | None = None,
    interrupt_after_record: int | None = None,
) -> dict[str, Any]:
    """Execute a complete or partial local batch run and return the finalized run report dictionary."""
    cfg = config or RunConfig()
    cfg.validate()

    active_run_id = run_id or f"run-{uuid.uuid4().hex[:12]}"
    ruleset_sha256 = get_ruleset_sha256(cfg.ruleset_id)
    config_sha256 = cfg.config_sha256()

    clf_adapter, sum_adapter = _init_optional_components(
        cfg, custom_summarizer_fn=custom_summarizer_fn
    )

    reader = BoundedJsonlReader(input_path=input_path, config=cfg)
    reader.validate_source_file()

    writer = StagingRunWriter(
        output_dir=output_dir,
        run_id=active_run_id,
        config=cfg,
        input_logical_name=str(Path(input_path).name),
    )
    writer.open()

    seen_alert_ids: set[str] = set()
    record_latencies_ms: list[float] = []
    classifier_latencies_ms: list[float] = []
    summarizer_latencies_ms: list[float] = []
    was_tracing = tracemalloc.is_tracing()
    if not was_tracing:
        tracemalloc.start()
    batch_start_ns = time.monotonic_ns()

    try:
        for raw_line in reader:
            result_rec = process_single_line(
                ingested=raw_line,
                run_id=active_run_id,
                config=cfg,
                seen_alert_ids=seen_alert_ids,
                classifier_adapter=clf_adapter,
                summarizer_adapter=sum_adapter,
                ruleset_sha256=ruleset_sha256,
                config_sha256=config_sha256,
            )
            writer.write_record(result_rec)
            record_latencies_ms.append(result_rec.timing.total_ns / 1_000_000.0)
            if cfg.enable_classifier and result_rec.processing_status == "accepted":
                classifier_latencies_ms.append(result_rec.timing.classifier_ns / 1_000_000.0)
            if cfg.enable_summarizer and result_rec.processing_status == "accepted":
                summarizer_latencies_ms.append(result_rec.timing.summarizer_ns / 1_000_000.0)

            if (
                cfg.batch_error_policy == "abort"
                and result_rec.processing_status in ("invalid", "failed")
            ):
                return writer.finalize_partial(
                    failure_reason=f"aborted_on_{result_rec.processing_status}_record_{raw_line.record_index}",
                    input_sha256=None,
                    promote_to_target=True,
                )

            if interrupt_after_record is not None and raw_line.record_index >= interrupt_after_record:
                raise KeyboardInterrupt("Simulated operator interruption")

        batch_wall_ms = (time.monotonic_ns() - batch_start_ns) / 1_000_000.0
        _, peak_bytes = tracemalloc.get_traced_memory()
        sorted_lat = sorted(record_latencies_ms)
        sorted_clf = sorted(classifier_latencies_ms)
        sorted_sum = sorted(summarizer_latencies_ms)
        extra_metrics: dict[str, Any] = {
            "batch_wall_ms": round(batch_wall_ms, 3),
            "records_per_second": (
                round((writer.total_lines / (batch_wall_ms / 1000.0)), 2)
                if batch_wall_ms > 0 and writer.total_lines > 0
                else 0.0
            ),
            "median_record_ms": round(_percentile(sorted_lat, 50.0), 4),
            "p95_record_ms": round(_percentile(sorted_lat, 95.0), 4),
            "p99_record_ms": round(_percentile(sorted_lat, 99.0), 4),
            "peak_traced_memory_mib": round(peak_bytes / (1024.0 * 1024.0), 4),
        }
        if sorted_clf:
            extra_metrics["classifier_median_ms"] = round(_percentile(sorted_clf, 50.0), 4)
            extra_metrics["classifier_p99_ms"] = round(_percentile(sorted_clf, 99.0), 4)
        if sorted_sum:
            extra_metrics["summarizer_median_ms"] = round(_percentile(sorted_sum, 50.0), 4)
            extra_metrics["summarizer_p95_ms"] = round(_percentile(sorted_sum, 95.0), 4)
            extra_metrics["summarizer_p99_ms"] = round(_percentile(sorted_sum, 99.0), 4)

        return writer.finalize_complete(
            input_sha256=reader.input_file_sha256,
            extra_metrics=extra_metrics,
        )
    except KeyboardInterrupt:
        writer.finalize_partial(
            failure_reason="interrupted_by_operator",
            input_sha256=None,
            promote_to_target=True,
        )
        raise
    except IngestionLimitError as exc:
        writer.finalize_partial(
            failure_reason=f"ingestion_limit:{exc.code}",
            input_sha256=None,
            promote_to_target=True,
        )
        raise
    except Exception:
        writer.finalize_partial(
            failure_reason="unhandled_batch_exception",
            input_sha256=None,
            promote_to_target=True,
        )
        raise
    finally:
        if not was_tracing and tracemalloc.is_tracing():
            tracemalloc.stop()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="triagelens",
        description="Offline-first deterministic & AI-assisted security alert triage CLI (demo-v1)",
    )
    parser.add_argument("--input", "-i", required=True, help="Path to input canonical JSONL file")
    parser.add_argument("--output-dir", "-o", required=True, help="Path to output run directory")
    parser.add_argument("--ruleset", default=RULESET_ID, help="Ruleset identifier (default: demo-v1)")
    parser.add_argument(
        "--mode",
        choices=("baseline", "ml", "llm", "ai"),
        default="baseline",
        help=(
            "Execution mode: 'baseline' (rules only), 'ml' (rules + P5 classifier), "
            "'llm' (rules + P6 local LLM summarizer), or 'ai' (rules + P5 classifier + P6 local LLM)"
        ),
    )
    parser.add_argument(
        "--ai-mode",
        "--ai",
        action="store_true",
        dest="ai_mode",
        help="Shortcut for --mode ai (enables both P5 advisory classifier and P6 local LLM summarizer)",
    )
    parser.add_argument(
        "--optional-mode",
        choices=("permissive", "strict"),
        default="permissive",
        help="Startup behavior when optional model prerequisites are unavailable (default: permissive)",
    )
    parser.add_argument(
        "--batch-error-policy",
        choices=("continue", "abort"),
        default="continue",
        help="Whether to continue or abort batch on invalid/failed records",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow replacing an existing output directory",
    )
    parser.add_argument(
        "--enable-classifier",
        action="store_true",
        help="Enable optional advisory linear classifier (defaults to models/triagelens_linear_v1.json)",
    )
    parser.add_argument(
        "--classifier-artifact",
        default=None,
        help="Path to verified JSON linear classifier artifact",
    )
    parser.add_argument(
        "--classifier-timeout-ms",
        type=int,
        default=200,
        help="Per-record timeout in ms for optional classifier (default: 200)",
    )
    parser.add_argument(
        "--enable-summarizer",
        action="store_true",
        help="Enable optional local LLM summarizer with template fallback",
    )
    parser.add_argument(
        "--summarizer-endpoint",
        default=None,
        help=f"Local loopback endpoint for optional summarizer (e.g. {DEFAULT_SUMMARIZER_ENDPOINT})",
    )
    parser.add_argument(
        "--summarizer-model",
        default=DEFAULT_SUMMARIZER_MODEL,
        help=f"Local LLM model tag for optional summarizer (default: {DEFAULT_SUMMARIZER_MODEL})",
    )
    parser.add_argument(
        "--summarizer-timeout-ms",
        type=int,
        default=10_000,
        help="Per-record timeout in ms for optional local summarizer (default: 10000)",
    )
    parser.add_argument(
        "--run-id",
        default=None,
        help="Optional explicit run identifier",
    )
    return parser


def _maybe_start_local_ollama_loopback(endpoint: str, model: str) -> Any:
    """Start local headless Ollama loopback daemon (and pull model on first run) if needed for 127.0.0.1:11434."""
    if endpoint not in ("http://127.0.0.1:11434", "http://localhost:11434"):
        return None
    ok, reason = verify_ollama_loopback_model(endpoint=endpoint, model=model, timeout_sec=1.0)
    if ok:
        return None

    import os
    import shutil
    import subprocess

    ollama_bin = shutil.which("ollama")
    if not ollama_bin:
        candidate = Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Ollama" / "ollama.exe"
        if candidate.is_file():
            ollama_bin = str(candidate)
    if not ollama_bin:
        return None

    proc = None
    try:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        if reason == "local_llm_unavailable":
            proc = subprocess.Popen(
                [ollama_bin, "serve"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=flags,
            )
            for _ in range(15):
                ok, reason = verify_ollama_loopback_model(
                    endpoint=endpoint, model=model, timeout_sec=1.0
                )
                if ok or (reason and reason.startswith("model_")):
                    break
                time.sleep(0.4)

        if not ok and reason == f"model_{model}_not_found_in_local_ollama":
            # First-time user setup: pull the requested local LLM into Ollama cache
            subprocess.run(
                [ollama_bin, "pull", model],
                check=False,
                creationflags=flags,
            )
            ok, _ = verify_ollama_loopback_model(endpoint=endpoint, model=model, timeout_sec=2.0)

        if ok:
            return proc
        if proc is not None:
            proc.terminate()
    except Exception:
        if proc is not None:
            try:
                proc.terminate()
            except Exception:
                pass
    return None


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    run_id = args.run_id or f"run-{uuid.uuid4().hex[:12]}"

    active_mode = "ai" if args.ai_mode else args.mode
    enable_clf = bool(args.enable_classifier) or active_mode in ("ml", "ai")
    enable_sum = bool(args.enable_summarizer) or active_mode in ("llm", "ai")

    # When summarizer is enabled on CLI without an explicit endpoint, default to local Ollama loopback
    sum_endpoint = args.summarizer_endpoint
    if enable_sum and sum_endpoint is None:
        sum_endpoint = DEFAULT_SUMMARIZER_ENDPOINT

    spawned_ollama = None
    try:
        if enable_sum and sum_endpoint is not None:
            spawned_ollama = _maybe_start_local_ollama_loopback(sum_endpoint, args.summarizer_model)

        config = RunConfig(
            ruleset_id=args.ruleset,
            optional_mode=args.optional_mode,
            batch_error_policy=args.batch_error_policy,
            overwrite=bool(args.overwrite),
            enable_classifier=enable_clf,
            classifier_artifact_path=args.classifier_artifact,
            classifier_timeout_ms=args.classifier_timeout_ms,
            enable_summarizer=enable_sum,
            summarizer_endpoint=sum_endpoint,
            summarizer_model=args.summarizer_model,
            summarizer_timeout_ms=args.summarizer_timeout_ms,
        )
        report = run_batch(
            input_path=args.input,
            output_dir=args.output_dir,
            config=config,
            run_id=run_id,
        )
        counts = report["counts"]
        diag = format_safe_diagnostic(
            run_id=report["run_id"],
            category=f"batch_{report['completion_state']}",
            detail=(
                f"mode={active_mode} classifier={enable_clf} summarizer={enable_sum} "
                f"total={counts['total_lines']} accepted={counts['accepted']} "
                f"invalid={counts['invalid']} failed={counts['failed']}"
            ),
        )
        print(diag, file=sys.stderr)
        return 0 if report["completion_state"] == "complete" else 2
    except (ConfigurationError, OutputDestinationError, UnsafeModelArtifactError) as exc:
        print(
            format_safe_diagnostic(run_id, "configuration_or_boundary_error", str(exc)),
            file=sys.stderr,
        )
        return 1
    except IngestionLimitError as exc:
        print(
            format_safe_diagnostic(run_id, f"ingestion_error:{exc.code}", exc.message),
            file=sys.stderr,
        )
        return 2
    except KeyboardInterrupt:
        print(
            format_safe_diagnostic(run_id, "interrupted", "Batch interrupted; partial report written"),
            file=sys.stderr,
        )
        return 130
    except Exception:
        print(
            format_safe_diagnostic(run_id, "fatal_error", "Unhandled internal error"),
            file=sys.stderr,
        )
        return 1
    finally:
        if spawned_ollama is not None:
            try:
                spawned_ollama.terminate()
                spawned_ollama.wait(timeout=3)
            except Exception:
                pass

