# ADR-0001: P0 Scope, Contracts, Hardware Baseline, and Dependency Selection

- **Status:** Accepted
- **Date:** 2026-10-08
- **Tasks Covered:** `P0-01`, `P0-02`, `P0-03`, `P0-04`
- **Governing Specifications:** `AGENTS.md`, `DESIGN.md`, `RULE_CATALOGUE.md`, `ARCHITECTURE.md`, `SECURITY.md`, `EVALUATION.md`, `RELEASE_GATES.md`, `HANDOFF.md`

---

## 1. Implementation Authorization and Workspace Audit (`P0-01`)

- **Authorization:** Explicit user instruction `"proceed with the implementation plan"` received on `2026-10-08T22:45:25+05:30`.
- **Scope:** **TriageLens** (offline-first local batch CLI for security alert triage). All **DocLift** artifacts and concepts (PDF extraction, OCR, invoice/marksheet schemas, HTTP upload endpoints, cloud deployment) remain excluded (`REQ-01`).
- **Workspace State:** Audited all 13 pre-existing Markdown specification documents (`AGENTS.md`, `README.md`, `implementation_plan.md`, `DESIGN.md`, `RULE_CATALOGUE.md`, `EXAMPLES.md`, `ARCHITECTURE.md`, `SECURITY.md`, `EVALUATION.md`, `HANDOFF.md`, `RELEASE_GATES.md`, `TRACEABILITY.md`, `DOMAIN_REVIEW.md`). All pre-existing user documentation files are preserved.

---

## 2. Target Environment, Data Rights, and Resource Budget Fields (`P0-02`)

### 2.1 Named Target Hardware and Runtime
- **Operating System:** Microsoft Windows 11 Home Single Language (Version `10.0.26200`, 64-bit)
- **Processor:** 13th Gen Intel(R) Core(TM) i5-13500H (12 physical cores, 16 logical processors)
- **System Memory:** `16,457,720 KiB` (`15.70 GiB`) total visible physical RAM (`4,472,716 KiB` / `4.27 GiB` free at pre-flight inspection)
- **Python Runtime:** Python `3.13.14` (`tags/v3.13.14:fd17997`, MSC v.1944 64-bit AMD64) in local `.venv`

### 2.2 Alert Source, CLI Scope, and Data Rights
- **Alert Source:** Local UTF-8 JSON Lines (`.jsonl`) conforming to canonical input contract `schema_version: "1.0"`.
- **CLI Scope:** Local single-process batch command-line interface (`python -m triagelens` / `triagelens`). No background daemon, web UI, database server, or network connector.
- **Data Rights & Model-Free Default:**
  - No customer, proprietary, or production telemetry exists in the workspace.
  - All test fixtures and the 200-alert benchmark use strictly synthetic, non-sensitive records (`INV-08`, `REQ-08`).
  - Because no independent labeled training dataset exists outside the 200-alert evaluation benchmark (which `P5` prohibits using as a training corpus), the **model-free rules + template baseline** is the default release configuration (`P5-01`).
  - Optional classifier advisory integration mechanics (`EXAMPLES.md` `L`–`N`, `G-11`, `G-15`) and optional local LLM containment/fallback (`EXAMPLES.md` `O`–`P`, `G-13`, `G-15`) are implemented and verified behind explicit opt-in flags, while shipping a trained production classifier (`G-12`) or bundled LLM weights (`G-14`) is recorded as `optional_skipped`.

### 2.3 Resource and Ingestion Ceilings (`REQ-04`, `REQ-13`)
- `max_input_file_bytes`: `104,857,600` (100 MiB)
- `max_records_per_run`: `10,000` records
- `max_record_bytes`: `1,048,576` (1 MiB per raw JSONL line, enforced prior to JSON parsing)
- `max_source_text_bytes`: `16,384` (16 KiB UTF-8 bytes and 16,384 codepoints)
- `max_json_depth`: `8` nesting levels
- `max_id_length`: `256` characters (`alert_id`, `source`, `event_name`)
- `max_entity_length`: `512` characters (`host`, `account`, `process`, `destination`, `metadata.source_record_ref`)
- **Provisional Runtime Budget Fields (to be measured in `P3-04` and frozen at `P4-04`):**
  - `baseline_batch_200_max_wall_ms`: `2,000 ms`
  - `baseline_record_p99_max_ms`: `10.0 ms`
  - `baseline_peak_tracemalloc_mib`: `64.0 MiB`
  - `optional_classifier_timeout_ms`: `200 ms`
  - `optional_summarizer_timeout_ms`: `2,000 ms`

---

## 3. Frozen Schema, Dispositions, Review Policy, and Architectural Decisions (`P0-03`)

### 3.1 Release Qualification Intent (`REQ-14`)
- **Target Release Level:** `Evaluated demonstration` (`RELEASE_GATES.md`).
- **Ruleset Status:** Ruleset `demo-v1` carries status `unvalidated_demo` (`DOMAIN_REVIEW.md`). Self-review counterexamples are documented in `DOMAIN_REVIEW.md` and explicitly labeled `self_review`; no external practitioner endorsement is claimed.

### 3.2 Canonical Input Envelope vs. Profile Contract (`REQ-02`, `REQ-03`)
- **Required Envelope Fields:**
  - `schema_version`: exact string `"1.0"`
  - `alert_id`: non-empty bounded string (`<= 256` chars), unique within a batch run (first valid occurrence retained; subsequent duplicates rejected as `invalid` with `duplicate_alert_id`). Never interpreted as a filesystem path.
  - `observed_at`: ISO-8601 timestamp string with explicit UTC offset (`Z` or `+HH:MM` / `-HH:MM`); normalized to UTC `YYYY-MM-DDTHH:MM:SSZ` (with microseconds preserved when non-zero). Naive timestamps without an offset are rejected (`invalid_timestamp`).
  - `family`: enum string in `{"authentication", "process", "network"}`. Unknown values produce `processing_status = "invalid"`, `disposition = null`, error code `"unsupported_family"` (`EXAMPLES.md` Case E).
  - `source`: non-empty bounded string (`<= 256` chars).
  - `event_name`: non-empty bounded string (`<= 256` chars).
  - `observations`: JSON object (`dict`).
- **Optional Envelope Fields:**
  - `source_severity`: enum string in `{"low", "medium", "high", "critical", "unknown"}` (or `null`).
  - `entities`: JSON object allowing only keys `{"host", "account", "process", "destination"}` with bounded string values (`<= 512` chars).
  - `source_text`: bounded string (`<= 16 KiB`), never used as a rule predicate or classifier feature, and excluded from LLM evidence packets (`INV-02`, `INV-04`).
  - `metadata`: JSON object allowing only `source_record_ref` (bounded string `<= 512` chars).
- **Strict Rejection Policy:**
  - Unknown top-level fields, forbidden label/split fields (`ground_truth`, `label`, `expected_disposition`, `split`, `scenario_family_id`, `template_lineage`), duplicate JSON keys within any object, non-finite numbers (`NaN`, `Infinity`), boolean-as-int or string-as-int coercions (`EXAMPLES.md` Case J), negative counts, `window_seconds < 1`, and blank lines are rejected with `processing_status = "invalid"` and `disposition = null` (`INV-05`).
- **Supported Event Profiles vs. Unknown Events:**
  - Supported profiles:
    1. `authentication` / `login_sequence`: essential fields `failed_attempts` (`int >= 0`), `window_seconds` (`int >= 1`), `success_after_failures` (`bool`), `approved_origin` (`bool`).
    2. `process` / `process_start`: essential fields `signature_status` (`"signed" | "unsigned" | "unknown"`), `location_category` (`"managed" | "user_writable" | "unknown"`), `approved_executable` (`bool`). Note: `"unknown"` for `signature_status` or `location_category` is schema-valid but constitutes incomplete evidence (`missing_evidence`).
    3. `network` / `connection_summary`: essential fields `connection_count` (`int >= 0`), `window_seconds` (`int >= 1`), `destination_blocklisted` (`bool`), `approved_destination` (`bool`).
  - Unknown `event_name` within a supported `family` (e.g., `authentication / password_reset`, `EXAMPLES.md` Case F) is schema-valid (`processing_status = "accepted"`) and produces `disposition = "needs_review"`, `review_reasons = ["unsupported_pattern"]`, with all `demo-v1` rules marked `not_applicable`.

### 3.3 Five Core Architectural Decisions (`ARCHITECTURE.md`)
1. **CLI vs. Service:** TriageLens is a local, synchronous batch CLI (`src/triagelens/cli.py`). No network listeners or persistent background services are used.
2. **Positive-Evidence Requirement for `likely_benign`:** A record receives `likely_benign` only if (a) all essential profile fields are present and known, (b) no contradiction (`contradictory_evidence`), policy conflict (`policy_conflict`), or suspicious rule match exists, and (c) an explicit benign candidate rule (`AUTH-B01`, `PROC-B01`, or `NET-B01`) matches (`INV-05`).
3. **Strict vs. Permissive Optional-Model Startup:** Controlled via `--optional-mode {permissive,strict}` (default `permissive`). In `permissive` mode, unavailable or failing optional models preserve the baseline decision and template summary while recording the failure state (`INV-07`). In `strict` mode, startup fails closed before processing records if an explicitly requested optional model cannot be verified.
4. **Safe Model Artifact Format:** Optional classifier artifacts must use the constrained JSON format `triagelens-linear-v1` (verified SHA-256 digest, explicit `feature_schema_id`, class list, and numeric weight/bias arrays). Object deserialization (`pickle`, `joblib`, `marshal`, `dill`) is prohibited (`SECURITY.md`).
5. **Batch Finalization Strategy:** Outputs are written to a staging directory `<output_dir>.staging.<pid>.<nonce>` on the same parent filesystem with `run_report.json` initialized to `"completion_state": "partial"`. Only after all records are processed and flushed is `run_report.json` updated to `"completion_state": "complete"` and the directory atomically renamed to `<output_dir>`. Existing `<output_dir>` paths are refused unless `--overwrite` is explicitly supplied (`P1-04`).

---

## 4. Dependency Selection and Verification (`P0-04`)

| Component | Selected Dependency | Version / License | Offline & Security Assessment |
| :--- | :--- | :--- | :--- |
| Core Runtime (`src/triagelens/`) | Python Standard Library only (`json`, `hashlib`, `datetime`, `argparse`, `dataclasses`, `pathlib`, `os`, `sys`, `time`, `shutil`, `socket`, `tracemalloc`) | Python `3.13.14` (PSF-2.0) | Zero third-party runtime dependencies; zero network imports; custom `json.loads` `object_pairs_hook` and `parse_constant` enforce duplicate-key and `NaN`/`Infinity` rejection (`INV-01`, `SECURITY.md`). |
| Test Suite (`tests/`) | Python `unittest` (stdlib) + `pytest` (local `.venv`) | Stdlib / MIT | Runs 100% offline with runtime socket egress denied (`INV-01`). |
