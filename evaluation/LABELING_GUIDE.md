# TriageLens Synthetic Benchmark Labeling Guide (`P4-01`, `REQ-08`)

- **Version:** `label-guide-v1`
- **Date Frozen:** `2026-10-08`
- **Applies To:** 200-alert synthetic evaluation benchmark (`evaluation/development/` and `evaluation/holdout/`)
- **Author & Review Protocol:** Single-author synthetic construction followed by a blinded second-pass verification audit (`EVALUATION.md`).

---

## 1. Separation of Underlying Scenario State and Expected Disposition

Every label record in `labels.jsonl` is stored **outside** the inference input (`alerts.jsonl`) and keyed by `alert_id` (`INV-08`). Each label distinguishes two separate concepts (`EVALUATION.md`):

1. **`underlying_scenario_state`** (`"malicious"`, `"benign"`, or `"ambiguous"`):
   - Describes what actually occurred in the simulated scenario (e.g., an attacker performing slow credential stuffing, a developer running a local unsigned build utility, or an endpoint sensor dropping a required telemetry field during a real attack).
2. **`expected_disposition`** (`"suspicious"`, `"likely_benign"`, or `"needs_review"`):
   - Describes the **evidence-sufficient triage decision** an analyst should expect given **only** the structured telemetry supplied in the alert record:
     - **`suspicious`**: The supplied observations contain complete, non-contradictory indicators that warrant prioritized investigation (including domain-suspicious patterns such as 8–9 rapid login failures from an unapproved origin followed by success, even when they fall just below a static rule threshold).
     - **`likely_benign`**: The supplied observations are complete, contain zero contradictions or policy conflicts, and provide positive benign evidence (e.g., approved origin with minimal retries, signed+managed+approved binary, or approved non-blocklisted destination) with no countervailing suspicious context.
     - **`needs_review`**: The supplied observations are incomplete (`missing_evidence`), internally contradictory (`contradictory_evidence` or `policy_conflict`), belong to an unrecognized event type within a supported family (`unsupported_pattern`), or present ambiguous/intermediate telemetry where neither `suspicious` nor `likely_benign` is justified from the record alone.

> **Important Rule (`EVALUATION.md`):** A scenario whose `underlying_scenario_state` is `"malicious"` MUST still be labeled `expected_disposition = "needs_review"` if the upstream sensor omitted essential telemetry (e.g., `window_seconds = null` or `signature_status = "unknown"`). TriageLens evaluates supplied evidence; it cannot guess missing telemetry.

---

## 2. Anti-Tautology and Domain Counterexample Policy (`DOMAIN_REVIEW.md`)

To prevent the benchmark from merely tautologically copying the `demo-v1` rule predicates:
- Scenario labels are assigned from scenario semantics and evidence sufficiency, **not** by running `demo-v1` rules as a label generator.
- The benchmark deliberately includes **domain counterexample lineages** where `demo-v1` rules and domain-labeled `expected_disposition` disagree:
  1. **Sub-threshold slow brute-force (`AUTH` counterexample):** 8–9 failed attempts within 180–240s from an unapproved origin followed by login success (`underlying_scenario_state = "malicious"`, `expected_disposition = "suspicious"`). Under `demo-v1`, `AUTH-S01` requires `failed_attempts >= 10`, so `demo-v1` predicts `needs_review` (`no_decisive_rule`), reducing `Suspicious recall`.
  2. **Post-rotation service retry spike (`AUTH` counterexample):** Automated batch service hitting 10–11 rapid failures after a scheduled credential rotation before succeeding (`underlying_scenario_state = "benign"`, `expected_disposition = "needs_review"` because origin is unapproved/staging). Under `demo-v1`, `AUTH-S01` predicts `suspicious`, creating a measured `Selective error` (`false suspicious`).
  3. **Unsigned local developer build binary (`PROC` counterexample):** Developer compiling a local test binary in a user-writable workspace (`underlying_scenario_state = "benign"`, `expected_disposition = "needs_review"`). Under `demo-v1`, `PROC-S01` predicts `suspicious`, contributing to `Selective error`.
  4. **Stale blocklist hit on reallocated cloud IP (`NET` counterexample):** Outbound connection to a stale blocklisted IP (`underlying_scenario_state = "benign"`, `expected_disposition = "needs_review"`). Under `demo-v1`, `NET-S01` predicts `suspicious`.

---

## 3. Grouped Split and Leakage Prevention Rules (`P4-03`, `INV-08`)

- **Population:** 200 syntactically valid alerts:
  - 60 `authentication` (`24` development, `36` holdout)
  - 60 `process` (`24` development, `36` holdout)
  - 60 `network` (`24` development, `36` holdout)
  - 20 `uncertainty` (incomplete, contradictory, policy-conflict, and unknown-event records distributed across the 3 families: `8` development, `12` holdout)
- **Group Independence:**
  - Every alert belongs to a `scenario_family_id` and `template_lineage`.
  - Development (`80` alerts) and Holdout (`120` alerts) use **completely disjoint** `scenario_family_id` and `template_lineage` sets.
  - Public examples `A`–`P` in `EXAMPLES.md` are excluded from both splits.
  - Inference records (`alerts.jsonl`) contain **zero** label, split, or lineage fields.
