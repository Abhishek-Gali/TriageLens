# ADR-0002: Optional Advisory Classifier (`P5`), Local Loopback Summarizer (`P6`), and `--optional-mode` CLI Policy

- **Status:** Accepted
- **Date:** `2026-10-08`
- **Task IDs:** `P5-01`–`P5-05`, `P6-01`–`P6-04`, `P7-02`
- **Invariants Governed:** `INV-01`, `INV-02`, `INV-03`, `INV-04`, `INV-05`, `INV-06`, `INV-07`, `INV-08`, `INV-09`, `INV-10`

---

## 1. Context

Following the completion of the deterministic model-free baseline (`P0`–`P4`), the operator authorized implementation of the optional classical advisory classifier (`P5`), the optional local LLM summarizer (`P6`), and explicit CLI option modes (`--optional-mode {permissive,strict}`).

Inspection of the operator's local workstation revealed:
- **Hardware:** 13th Gen Intel Core i5-13500H (12 cores / 16 threads), Intel Iris Xe Graphics (`1 GiB` shared adapter memory), `15.70 GiB` total RAM (`~4.27 GiB` available free physical RAM).
- **Python ML Stack (`.venv`):** `scikit-learn 1.8.0`, `numpy 2.3.5`, `scipy 1.17.0`, `onnxruntime 1.29.0`.
- **Local LLM Runtime (`Ollama 0.34.0`):** Locally cached GGUF models on disk (`C:\Users\galia\.ollama\models`):
  - `qwen2.5:1.5b` (`986 MB`)
  - `qwen2.5:0.5b` (`398 MB`)
  - `qwen3:0.6b` (`523 MB`)
  - `chloe:latest` (`986 MB`)
  - `qwen2.5vl:3b` (`3.2 GB`, multimodal vision-language)
  - `qwen2.5-coder:7b` (`4.7 GB`, exceeds available free RAM)

---

## 2. Decisions

### 2.1 `P5` Advisory Classifier: `scikit-learn` `LogisticRegression` Exported to Verified JSON (`triagelens-linear-v1`)

1. **Independent Training Corpus (`P5-01`):**
   - To preserve `INV-08` and prevent benchmark contamination, the classifier is never trained on `evaluation/development/` or `evaluation/holdout/`.
   - `evaluation/train_classifier.py` constructs a separate synthetic training split (`240` alerts across `TRAIN-*` lineages) and validation split (`60` alerts across `VAL-*` lineages) in `evaluation/training/`, plus a fresh 120-alert `P5/P6` grouped holdout (`HOLD2-*`) in `evaluation/holdout_p5p6/`.
2. **Leakage-Safe Featurization & Model Export (`P5-02`):**
   - `StandardScaler` is fit strictly on `X_train` (`240 x 16` numeric feature matrix defined by `triagelens-feat-v1`) prior to fitting `LogisticRegression(C=1.0, solver='lbfgs', random_state=42)`.
   - Rather than serializing Python objects via `pickle` or `joblib` (forbidden by `SECURITY.md` and `G-11`), the scaler parameters (`mean_`, `scale_`) and logistic regression weights (`coef_`, `intercept_`) are algebraically folded into raw feature weights and bias and exported to `models/triagelens_linear_v1.json` with SHA-256 verification.
   - Consequently, the runtime package `src/triagelens/` remains 100% Python standard library with sub-millisecond inference (`0.0255 ms` median per alert).
3. **Escalation-Only Policy (`INV-03`, `G-12`):**
   - When enabled (`--enable-classifier`), the classifier can only escalate a decisive baseline verdict (`suspicious` or `likely_benign`) to `needs_review` with `classifier_disagreement` while preserving `baseline_disposition`. It never promotes `needs_review` to a decisive disposition.

### 2.2 `P6` Local Summarizer: `qwen2.5:1.5b` via Loopback Ollama (`http://127.0.0.1:11434`)

1. **Model Selection:**
   - `qwen2.5:1.5b` (`986 MB`) fits comfortably within the machine's `~4.27 GiB` free physical RAM without paging, follows structured two-sentence JSON summarization instructions reliably, and avoids the memory pressure of `qwen2.5-coder:7b` (`4.7 GB`) or the vision overhead of `qwen2.5vl:3b` (`3.2 GB`).
2. **Loopback Containment & Evidence Packet (`INV-01`, `INV-04`, `G-13`):**
   - `RunConfig.validate()` and `make_ollama_loopback_generator()` enforce that `--summarizer-endpoint` binds strictly to `http://127.0.0.1:<port>` or `http://localhost:<port>`. Any remote hostname or IP is rejected.
   - The LLM receives only `RestrictedEvidencePacket` (`family`, `event_name`, `baseline_disposition`, `disposition`, `review_reasons`, `matched_rule_ids`, `cited_observations`). Untrusted `source_text`, `entities`, `metadata`, and `alert_id` are never sent to the LLM.
3. **Candidate Validation & Template Fallback (`INV-07`, `G-14`, `G-15`):**
   - Every candidate summary is checked by `validate_candidate_summary()` for length (`<= 512` chars), presence of the frozen disposition, absence of contradictory dispositions, and absence of unsupported breach/remediation/command claims. Any failure or timeout falls back to the deterministic `explain-v1` template.

### 2.3 CLI Option Modes (`--optional-mode {permissive,strict}`)

- `--optional-mode permissive` (default): If an enabled optional component (`--enable-classifier` or `--enable-summarizer`) cannot find its artifact or reach the local loopback server, or times out during a batch, TriageLens records the fallback (`optional_classifier.state = "unavailable"` / `"failed"`, or `summary.validation_state = "failed_fallback"` / `"rejected_fallback"`) and completes the deterministic baseline run (`exit code 0`). Note: unsafe model artifacts (`.pkl`/`.joblib`/bad hash) and non-loopback URLs are still rejected immediately (`exit code 1`).
- `--optional-mode strict`: Requires all enabled optional components to be present, verified, and reachable at startup; missing classifier artifacts or unreachable loopback LLM servers abort startup with `ConfigurationError` (`exit code 1`).
