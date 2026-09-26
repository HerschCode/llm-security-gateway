# Security scans and appsec hygiene (Phase 6)

Run on 2026-09-25 against commit `13b8fbb` plus the changes in the Phase 6 commit; the CI-only tools were read for the first time on 2026-09-26 (below). This is what each tool found, what was fixed, what was accepted and why,
and, just as important, what could **not** be run here. The threat model that ties these together is [`SECURITY.md`](../SECURITY.md).

## Which tools ran where

| Tool | Version | Ran locally | In CI | Result |
|---|---|---|---|---|
| pip-audit | 2.10.1 | yes | `ci.yml` `dependencies`, **blocking** | 0 known vulnerabilities in 24 packages (serving set) and 38 (full set) |
| Bandit | 1.9.4 | yes | `security.yml` `bandit`, **blocking** | 48 findings (3 HIGH, 13 MEDIUM, 32 LOW) before; **0 HIGH, 0 MEDIUM, 26 LOW** after; `gateway/` has none |
| detect-secrets | 1.5.0 | yes (stand-in) | no | 3 candidates before, 5 after; all false positives (below) |
| Git-history secret scan | grep, 11 token formats | yes (stand-in for gitleaks) | no | 0 matches in 72 commits |
| gitleaks | action v2.3.9 | **no** | `security.yml` `gitleaks`, blocking, full history | **passed** in CI on 2026-09-26 (the report was not read: a pass means no match under `.gitleaks.toml`) |
| Semgrep | 1.178.0 | **no**: `semgrep-core` exits with an error on this Windows machine even for a one-line rule | `security.yml` `semgrep`, **blocking** since 2026-09-26 | first CI run: 13 warnings; 3 fixed, 10 accepted with a reason beside the code, 0 unsuppressed (triage below) |
| Trivy (filesystem) | action v0.36.0 | **no** (no binary downloaded) | `security.yml` `trivy-fs`, blocking | **passed** in CI (fixed HIGH or CRITICAL vulnerabilities, secrets and misconfigurations; the report was not read) |
| Trivy (image) | action v0.36.0 | **no** (no Docker daemon here) | `security.yml` `trivy-image`, **blocking** since 2026-09-26 | CI built `Dockerfile.render` and the scan passed (no fixed HIGH or CRITICAL); the full-mode `Dockerfile` (with torch) is not built anywhere yet |
| CycloneDX SBOM | cyclonedx-bom 7.4.0 | yes (sample in `sbom/`) | `sbom.yml` on release, unrun | 23 components; hashes stay in the lock file, not the SBOM |
| Lock verification | `pip download --require-hashes` | yes | | all 23 wheels of the serving lock downloaded and matched their hash (Linux, CPython 3.12) |
| Workflow validation | check-jsonschema 0.38.1 | yes | | all four config files valid against GitHub's schemas; `ci.yml` and `security.yml` have run on GitHub on every push since the Phase 6 commit (`sbom.yml` runs on release and has not) |

Semgrep, Trivy and gitleaks cannot run on the maintainer's machine, so their first run was in CI, and they were not read until 2026-09-26: `ci.yml` had been failing since the
Phase 6 push (a Linux-only test failure, see `decisions.md`, 2026-09-26) and the Security workflow's results had not been looked at. After the triage below, Semgrep and the image scan
were made blocking, and `tests/test_supply_chain.py` now pins that only the style linter may soften. Read "passed" as "nothing above the configured threshold": the Trivy and gitleaks
reports need a login to download and were not read, and the tools were not run inside a container here.

## Semgrep triage (first CI run, 2026-09-26)

13 warnings from `p/python`, `p/security-audit` and `p/owasp-top-ten` on 102 tracked files. A suppression is written as `# nosemgrep: <rule id> - <reason>` beside the code so a reader
sees why; Semgrep still lists it, marked suppressed, and a rule id has to match exactly (one was wrong on the first try and its finding stayed blocking).

| Rule | Where | Decision |
|---|---|---|
| `dependabot-missing-cooldown` (3) | `.github/dependabot.yml` | **Fixed**: `cooldown: default-days: 7` on every ecosystem, so a release is proposed only after a week |
| `avoid-pickle`, 2 loads and 2 writes | `gateway/detectors/embedding_similarity.py` | Accepted. The loads are SHA-256 checked against `models/MANIFEST.sha256` first (SEC-05); the writes are training-time; the layer is off by default |
| `avoid-pickle`, 1 load and 1 write | `gateway/detectors/embedding_similarity_st.py` | Accepted, same reasons (opt-in layer) |
| `avoid-pickle`, 1 write | `scripts/distill_to_student.py` | Accepted: a training-script write of an experiment file the gateway never loads |
| `dangerous-subprocess-use-tainted-env-args` | `redteam/run_garak.py` | Accepted: an argv list with no shell, run by the maintainer with their own arguments (Bandit's equivalent was accepted for the same call) |
| `insecure-hash-algorithm-sha1` | `scripts/baselines/run_guard_hosted.py` | Accepted: a cache key with `usedforsecurity=False` (SEC-10); changing it would discard the cached hosted-API scores, which cost quota |
| `dynamic-urllib-use-detected` | `scripts/prepare_training_data.py` | Accepted: a constant https URL whose scheme is checked before use (Bandit B310, same call) |

Ten of the thirteen are suppressions, not fixes. Each is a judgement that should be revisited if the code around it changes; a new Semgrep finding now fails the build.

## Findings and what was done

Numbering: **SEC-nn**. The first two were found by threat modelling and measurement, not by any scanner.

| ID | Finding | Source | Severity | Action |
|---|---|---|---|---|
| SEC-01 | No limit on the request: `ChatRequest.prompt` was an unbounded string and no route limited the body, so one large request used the CPU and memory of a 512 MB instance in the PII regexes, normalizer and classifier, and the session context would have kept it. | threat model | High (availability) | **Fixed**: prompt cap (20,000 chars), bounded identity fields, a 256 KiB body limit on every route that also stops chunked uploads (`gateway/limits.py`, `tests/test_limits.py`, 14 tests). |
| SEC-02 | Quadratic regex: the email pattern rescanned a whole run of local-part characters from every position when no `@` followed: **270 ms for 20,000 characters of plain `a`** (50x every other step), so a large request cost far more CPU than its size suggests. | measurement | Medium | **Fixed**: a lookbehind makes it linear (3.4 ms at 20,000; 26 ms at 200,000). `tests/test_input_scaling.py` checks the scaling of 7 steps on 11 hostile shapes and was shown to fail on the old pattern (ratio 4.0 against a limit of 3.3). |
| SEC-03 | Bandit B613, "Trojan Source": `gateway/text_normalizer.py` held its zero-width-character regex as literal invisible characters (including U+200E and U+200F), invisible to any reviewer. 36 such literals in 4 files in all. | Bandit | High | **Fixed**: every one is a visible `\uXXXX` escape (behaviour unchanged, 120 related tests pass); `tests/test_source_hygiene.py` fails on any invisible, format, combining or bidirectional character in any Python file. |
| SEC-04 | B202: `tarfile.extractall` on a downloaded tarball with no validation (path traversal, links; CVE-2007-4559). | Bandit | High | **Fixed**: `safe_extract` refuses members that leave the destination and any link or special file, before extracting anything; https-only download check (B310). `tests/test_appsec_fixes.py`. |
| SEC-05 | B301/B403: `pickle.load` of the layer-2 vectorizer and known-bad index (three loads). Pickle runs code chosen by the file's author. | Bandit | Medium | **Mitigated** (the loads remain): SHA-256 of each served artifact is checked against a committed `models/MANIFEST.sha256` before loading; enforced in both images and in CI, a warning elsewhere so retraining still works; `.gitattributes` marks `models/` binary so git cannot rewrite the bytes. `tests/test_model_integrity.py` (14 tests) includes a hostile pickle that is refused before it can run. Limit: it detects change, not intent. |
| SEC-06 | B615: eight Hugging Face `from_pretrained` calls with no revision, i.e. "whatever is latest". | Bandit | Medium | **Fixed**: revisions pinned (ProtectAI to the exact commit whose weights were evaluated here; Meta's two models; DistilBERT). Four calls on local fine-tuned checkpoints carry `nosec B615` with the reason. |
| SEC-07 | B614: `torch.load` without `weights_only`. | Bandit | Medium | **Fixed**: `weights_only=True` (the file is a state dict). |
| SEC-08 | The images ran as root, installed unhashed and unpinned dependencies, used a floating base tag, and (the full image) copied the whole build context, including virtual environments, logs and the approvals database. | review | Medium | **Fixed in the Dockerfiles** (not built locally): digest-pinned base, `--require-hashes` from lock files, non-root user with only `logs/` writable, `MODEL_INTEGRITY=enforce`, a `.dockerignore` that excludes venvs, `logs/`, reports, red-team output and secret-like files. `tests/test_supply_chain.py` pins each property. |
| SEC-09 | CI actions referenced by mutable tags, no `permissions`, tools installed unpinned. | review | Medium | **Fixed**: every action is a full commit SHA, `permissions: contents: read`, tools installed from `requirements-ci.lock` with hashes; both are tested. |
| SEC-10 | B324: SHA-1 as a cache key in an evaluation script. | Bandit | High (rule), none in practice | **Fixed** with `usedforsecurity=False` (a cache key, not a security use). |
| SEC-11 | B110: `except: pass` in the base64/hex decoders and a report parser. | Bandit | Low | **Fixed**: they catch `ValueError` (which covers `binascii.Error` and `UnicodeDecodeError`) and say why. |

## Accepted, with the reason

| Finding | Where | Why accepted |
|---|---|---|
| B603 / B404, subprocess | `gateway/actions/mcp_proxy.py` (inline `nosec`) | The upstream command is the operator's own argv, never request data, and no shell is involved. |
| B603 / B404 (9 + 4) | dev scripts (`scripts/`, `redteam/run_garak.py`) | Fixed argv lists run by the developer on their own machine. Bandit runs on these at medium severity and above. |
| B311, `random` (11) | evaluation and training scripts | Seeded sampling for reproducible data splits, not security. A test asserts `gateway/` never imports `random`, so nothing security-relevant can use it. |
| B101, `assert` (1) | `scripts/recalibrate_thresholds.py` | A developer-run script. |
| B403, pickle import (1) | `scripts/distill_to_student.py` | Writes and reads a local experiment file the gateway never loads. |
| detect-secrets: 3 hex strings | `scripts/baselines/run_guard_baselines.py`, `scripts/train_distilbert_finetune.py` | Public Hugging Face commit SHAs. |
| detect-secrets: base64-shaped string | `gateway/text_normalizer.py` | The Atbash alphabet. |
| detect-secrets: hex string | `tests/test_pii_indian.py` | A PAN-shaped test value. |
| The Postgres password `local-dev-only` | `docker-compose.trilogy.yml` | A throwaway credential for a compose network that publishes no database port; marked `pragma: allowlist secret` and allowlisted in `.gitleaks.toml`. |

## Supply chain

- **Lock files with hashes**: `requirements-render.lock` (23 packages, serving), `requirements.lock` (56, full set with torch), `requirements-ci.lock` (106, the scanners and test tools). Compiled for Linux and CPython 3.12
  with `uv` (`scripts/update_locks.sh`) and installed with `--require-hashes --no-deps`. The serving lock was verified end to end against PyPI. The full lock was not downloaded (it resolves the CUDA build of torch, several GB).
  Dependabot updates the `requirements*.txt` inputs but does not regenerate locks: run the script on its branch.
- **SBOM**: `sbom.yml` produces a CycloneDX 1.6 SBOM of the Python dependencies (from the locks) and of the built image (Trivy) and attaches them to each release. A sample generated locally is in `sbom/`. The SBOM lists names,
  versions and package URLs; the hashes live in the lock files.
- **Pins**: actions to commit SHAs, base image to a digest (kept identical in both Dockerfiles by a test, because Dependabot may not see `Dockerfile.render`).

## Reproduce

```bash
python -m venv .venv-sec && .venv-sec/Scripts/python -m pip install pip-audit bandit cyclonedx-bom detect-secrets uv check-jsonschema
.venv-sec/Scripts/pip-audit -r requirements-render.lock --require-hashes
.venv-sec/Scripts/bandit -r gateway -q                                              # any finding fails
.venv-sec/Scripts/bandit -r scripts project2_agent redteam --exclude redteam/.venv-garak,redteam/runs --severity-level medium -q
.venv-sec/Scripts/cyclonedx-py requirements requirements-render.lock --of JSON --sv 1.6 -o sbom/sbom-python-render.cdx.json
.venv-sec/Scripts/check-jsonschema --builtin-schema vendor.github-workflows .github/workflows/*.yml
python -m pytest tests/test_supply_chain.py tests/test_source_hygiene.py tests/test_model_integrity.py tests/test_limits.py tests/test_input_scaling.py tests/test_appsec_fixes.py
```
