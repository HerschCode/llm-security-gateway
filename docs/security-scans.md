# Security scans and appsec hygiene (Phase 6)

Run on 2026-09-25 against commit `13b8fbb` plus the changes in the Phase 6 commit. This is what each tool found, what was fixed, what was accepted and why,
and, just as important, what could **not** be run here. The threat model that ties these together is [`SECURITY.md`](../SECURITY.md).

## Which tools ran where

| Tool | Version | Ran locally | In CI | Result |
|---|---|---|---|---|
| pip-audit | 2.10.1 | yes | `ci.yml` `dependencies`, **blocking** | 0 known vulnerabilities in 24 packages (serving set) and 38 (full set) |
| Bandit | 1.9.4 | yes | `security.yml` `bandit`, **blocking** | 48 findings (3 HIGH, 13 MEDIUM, 32 LOW) before; **0 HIGH, 0 MEDIUM, 26 LOW** after; `gateway/` has none |
| detect-secrets | 1.5.0 | yes (stand-in) | no | 3 candidates before, 5 after; all false positives (below) |
| Git-history secret scan | grep, 11 token formats | yes (stand-in for gitleaks) | no | 0 matches in 72 commits |
| gitleaks | action v2.3.9 | **no** | `security.yml` `gitleaks`, blocking, full history | not run by the author |
| Semgrep | 1.178.0 | **no**: `semgrep-core` exits with an error on this Windows machine even for a one-line rule | `security.yml` `semgrep`, **non-blocking** | findings unknown |
| Trivy (filesystem) | action v0.36.0 | **no** (no binary downloaded) | `security.yml` `trivy-fs`, blocking | not run by the author |
| Trivy (image) | action v0.36.0 | **no** (no Docker daemon here) | `security.yml` `trivy-image`, **non-blocking** | not run; the image has not been built locally |
| CycloneDX SBOM | cyclonedx-bom 7.4.0 | yes (sample in `sbom/`) | `sbom.yml` on release, unrun | 23 components; hashes stay in the lock file, not the SBOM |
| Lock verification | `pip download --require-hashes` | yes | | all 23 wheels of the serving lock downloaded and matched their hash (Linux, CPython 3.12) |
| Workflow validation | check-jsonschema 0.38.1 | yes | | all four config files valid against GitHub's schemas; **the workflows have not been executed on GitHub** |

The three scanners that could not be run locally are configured so they run in CI, and the two whose first findings are unknown (Semgrep, the image scan) are
non-blocking on purpose: making them blocking before anyone has seen their output would either fail the build on day one or invite a blanket suppression.
`tests/test_supply_chain.py` pins which jobs are allowed to soften (`lint`, `semgrep`, `trivy-image`), so making another one soft is a visible test change. **To close
this gap:** start Docker Desktop and run `semgrep/semgrep`, `aquasec/trivy` and `zricethezav/gitleaks` against the repository, triage, then flip the two jobs to blocking.

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
