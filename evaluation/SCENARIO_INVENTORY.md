# TriageLens Synthetic Scenario Inventory (`P4-01`, `P4-02`, `P4-03`)

- **Total Valid Evaluation Alerts:** `200` (`80` Development / `120` Sealed Holdout)
- **Split Strategy:** Grouped by `scenario_family_id` and `template_lineage` (zero overlap between Development and Holdout; zero overlap with `EXAMPLES.md` `A`–`P`).

---

## 1. Allocation by Slice and Split

| Slice Category | Alert Family | Development (`80`) | Holdout (`120`) | Total (`200`) |
| :--- | :--- | :---: | :---: | :---: |
| Standard Authentication | `authentication` | 24 | 36 | 60 |
| Standard Process | `process` | 24 | 36 | 60 |
| Standard Network | `network` | 24 | 36 | 60 |
| Uncertainty / Incomplete / Conflict / Unknown Event | `authentication`, `process`, `network` | 8 | 12 | 20 |
| **Total** | **All Supported Families** | **80** | **120** | **200** |

---

## 2. Development Split Scenario Lineages (`80` Alerts, `DEV-*`)

| Scenario Family ID | Template Lineage | Family / Event | Count | Underlying State | Expected Disposition | Scenario Description |
| :--- | :--- | :--- | :---: | :--- | :--- | :--- |
| `DEV-AUTH-BF-01` | `lin-dev-auth-ssh-bruteforce` | `authentication / login_sequence` | 7 | `malicious` | `suspicious` | Rapid SSH password brute-force (12–45 failures in 60–280s) followed by login from unapproved external origin. |
| `DEV-AUTH-ROT-02` | `lin-dev-auth-service-rotation` | `authentication / login_sequence` | 1 | `benign` | `needs_review` | Domain counterexample: staging service retrying 11 times in 200s after credential rotation on unapproved subnet (`AUTH-S01` fires $\rightarrow$ selective error). |
| `DEV-AUTH-SLOW-03` | `lin-dev-auth-slow-stuffing` | `authentication / login_sequence` | 2 | `malicious` | `suspicious` | Domain counterexample: low-and-slow credential stuffing with 8–9 failures in 210s from unapproved origin followed by login (`AUTH-S01` misses $\rightarrow$ review). |
| `DEV-AUTH-SSO-04` | `lin-dev-auth-corp-sso` | `authentication / login_sequence` | 8 | `benign` | `likely_benign` | Routine corporate SSO login with 0–2 password typos within 45–240s from an approved workstation origin. |
| `DEV-AUTH-AMB-05` | `lin-dev-auth-unapproved-roaming` | `authentication / login_sequence` | 6 | `ambiguous` | `needs_review` | Intermediate failure counts (3–7 failures) or login from unapproved hotel/roaming origin without brute-force burst. |
| `DEV-PROC-DROP-01` | `lin-dev-proc-temp-dropper` | `process / process_start` | 7 | `malicious` | `suspicious` | Unsigned payload executed from user-writable temporary/downloads directory (`approved_executable=false`). |
| `DEV-PROC-DEVBUILD-02` | `lin-dev-proc-local-compiler` | `process / process_start` | 1 | `benign` | `needs_review` | Domain counterexample: unsigned developer unit-test binary executed in user-writable build folder (`PROC-S01` fires $\rightarrow$ selective error). |
| `DEV-PROC-CORP-03` | `lin-dev-proc-managed-agent` | `process / process_start` | 8 | `benign` | `likely_benign` | Signed, approved enterprise management binary started from managed system directory. |
| `DEV-PROC-UNAPP-04` | `lin-dev-proc-thirdparty-signed` | `process / process_start` | 8 | `ambiguous` | `needs_review` | Signed third-party utility not on executable allowlist (`approved_executable=false`) or unsigned binary in managed path. |
| `DEV-NET-C2-01` | `lin-dev-net-blocklist-beacon` | `network / connection_summary` | 7 | `malicious` | `suspicious` | Outbound connections (2–25 connections in 30–300s) to blocklisted C2 destination (`approved_destination=false`). |
| `DEV-NET-STALE-02` | `lin-dev-net-stale-cdn-blocklist` | `network / connection_summary` | 1 | `benign` | `needs_review` | Domain counterexample: single connection to a stale blocklist IP reallocated to a public CDN (`NET-S01` fires $\rightarrow$ selective error). |
| `DEV-NET-SAAS-03` | `lin-dev-net-approved-telemetry` | `network / connection_summary` | 8 | `benign` | `likely_benign` | Routine outbound connections (1–40 connections) to approved, non-blocklisted enterprise update/telemetry service. |
| `DEV-NET-UNCAT-04` | `lin-dev-net-uncategorized-ext` | `network / connection_summary` | 8 | `ambiguous` | `needs_review` | Outbound traffic to uncategorized external host (`destination_blocklisted=false, approved_destination=false`) or zero-connection summary. |
| `DEV-UNC-01` | `lin-dev-unc-missing-and-conflicts` | Mixed (`authentication`, `process`, `network`) | 8 | `ambiguous` / `malicious` | `needs_review` | Intentional missing observations (`window_seconds=null`, `signature_status='unknown'`), network `contradictory_evidence`, process `policy_conflict`, and unknown events (`mfa_enrollment`, `module_load`, `dns_lookup`). |

---

## 3. Sealed Holdout Split Scenario Lineages (`120` Alerts, `HOLD-*`)

| Scenario Family ID | Template Lineage | Family / Event | Count | Underlying State | Expected Disposition | Scenario Description |
| :--- | :--- | :--- | :---: | :--- | :--- | :--- |
| `HOLD-AUTH-SPRAY-01` | `lin-hold-auth-vpn-spray` | `authentication / login_sequence` | 11 | `malicious` | `suspicious` | VPN gateway password spray/burst (10–60 failures in 45–300s) followed by session establishment from unapproved origin. |
| `HOLD-AUTH-BATCH-02` | `lin-hold-auth-legacy-cron` | `authentication / login_sequence` | 1 | `benign` | `needs_review` | Domain counterexample: legacy batch script retrying 12 times in 240s after vault sync delay on unapproved lab host (`AUTH-S01` fires $\rightarrow$ selective error). |
| `HOLD-AUTH-LOWSLOW-03` | `lin-hold-auth-paced-intrusion` | `authentication / login_sequence` | 2 | `malicious` | `suspicious` | Domain counterexample: paced attacker login sequence with 8–9 failures in 250s from unapproved origin (`AUTH-S01` misses $\rightarrow$ review). |
| `HOLD-AUTH-WORK-04` | `lin-hold-auth-workstation-unlock` | `authentication / login_sequence` | 12 | `benign` | `likely_benign` | Managed workstation login sequence with 0–2 failed attempts from approved corporate origin. |
| `HOLD-AUTH-BORDER-05` | `lin-hold-auth-window-and-unapproved` | `authentication / login_sequence` | 10 | `ambiguous` | `needs_review` | Login failures over extended windows (`>300s`), failed bursts without success (`success_after_failures=false`), or unapproved origin with 1–5 failures. |
| `HOLD-PROC-STAGE-01` | `lin-hold-proc-appdata-stage` | `process / process_start` | 11 | `malicious` | `suspicious` | Unsigned stager binary launched from user-writable profile directory (`approved_executable=false`). |
| `HOLD-PROC-LABTOOL-02` | `lin-hold-proc-qa-harness` | `process / process_start` | 1 | `benign` | `needs_review` | Domain counterexample: unsigned internal QA test harness run from user-writable directory (`PROC-S01` fires $\rightarrow$ selective error). |
| `HOLD-PROC-SYS-03` | `lin-hold-proc-signed-system` | `process / process_start` | 12 | `benign` | `likely_benign` | Signed, approved operating-system or endpoint service binary started from managed path. |
| `HOLD-PROC-GRAY-04` | `lin-hold-proc-unapproved-vendor` | `process / process_start` | 12 | `ambiguous` | `needs_review` | Signed vendor utility not in approved executable list or signed binary running from user-writable path. |
| `HOLD-NET-BOT-01` | `lin-hold-net-malware-callback` | `network / connection_summary` | 11 | `malicious` | `suspicious` | Outbound callback connections (1–50 connections) to blocklisted command-and-control endpoint (`approved_destination=false`). |
| `HOLD-NET-REUSEDIP-02` | `lin-hold-net-reallocated-cloud-ip` | `network / connection_summary` | 1 | `benign` | `needs_review` | Domain counterexample: outbound connection to a reallocated cloud IP still present on an upstream blocklist (`NET-S01` fires $\rightarrow$ selective error). |
| `HOLD-NET-REPO-03` | `lin-hold-net-approved-mirror` | `network / connection_summary` | 12 | `benign` | `likely_benign` | Outbound connections to approved, non-blocklisted internal package mirror / patch repository. |
| `HOLD-NET-UNKNOWN-04` | `lin-hold-net-unlisted-partner` | `network / connection_summary` | 12 | `ambiguous` | `needs_review` | Connections to unapproved external partner endpoint (`destination_blocklisted=false, approved_destination=false`) or zero-connection summary. |
| `HOLD-UNC-01` | `lin-hold-unc-incomplete-and-conflict` | Mixed (`authentication`, `process`, `network`) | 12 | `ambiguous` / `malicious` | `needs_review` | Missing essential observations (`failed_attempts=null`, `location_category='unknown'`, `approved_destination=null`), `contradictory_evidence`, `policy_conflict`, and unknown events (`token_refresh`, `script_block`, `tls_handshake`). |
