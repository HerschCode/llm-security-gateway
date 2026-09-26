"""Guards for the Phase 6 supply-chain properties, so a later edit cannot quietly weaken them:

  * every third-party GitHub Action is pinned to a full commit SHA and every workflow declares permissions;
  * the workflows that gate security are not softened (only the listed jobs may continue-on-error);
  * the Docker images pin their base by digest, install with --require-hashes, run unprivileged and enforce model integrity;
  * every package in every lock file has a hash, and each lock covers the requirements it was compiled from.
"""
import re
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
WORKFLOWS = sorted((REPO / ".github" / "workflows").glob("*.yml"))

# Jobs allowed to continue-on-error, each for a stated reason in its workflow file. Semgrep and the image scan were soft until their first findings were
# triaged (2026-09-26); only the style linter still is.
SOFT_JOBS = {"lint"}


def load(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def all_uses(wf):
    for job in (wf.get("jobs") or {}).values():
        for step in job.get("steps") or []:
            if "uses" in step:
                yield step["uses"]


def test_there_are_workflows():
    assert {p.name for p in WORKFLOWS} >= {"ci.yml", "security.yml", "sbom.yml"}


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_action_is_pinned_to_a_full_commit_sha(path):
    for uses in all_uses(load(path)):
        if uses.startswith("./") or uses.startswith("docker://"):
            continue
        assert re.search(r"@[0-9a-f]{40}$", uses), f"{path.name}: {uses} is not pinned to a commit SHA"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_workflow_declares_least_privilege_permissions(path):
    wf = load(path)
    assert "permissions" in wf, f"{path.name} has no top-level permissions block"
    assert wf["permissions"] in ({"contents": "read"}, {}), wf["permissions"]


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_no_workflow_uses_pull_request_target(path):
    triggers = load(path).get(True) or load(path).get("on") or {}
    assert "pull_request_target" not in triggers


def test_only_the_documented_jobs_are_allowed_to_fail_without_failing_the_build():
    soft = set()
    for path in WORKFLOWS:
        for name, job in (load(path).get("jobs") or {}).items():
            if job.get("continue-on-error") or any(step.get("continue-on-error") for step in job.get("steps") or []):
                soft.add(name)
    assert soft == SOFT_JOBS, f"security gates changed: {sorted(soft ^ SOFT_JOBS)}"


def test_the_security_workflow_runs_the_scanners_it_claims_to():
    text = (REPO / ".github" / "workflows" / "security.yml").read_text(encoding="utf-8")
    for needle in ("bandit -r gateway", "semgrep scan", "gitleaks/gitleaks-action", "aquasecurity/trivy-action", "cron:"):
        assert needle in text, needle


def test_ci_installs_from_hash_locked_files_and_enforces_model_integrity():
    text = (REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "--require-hashes" in text and "requirements-render.lock" in text and "MODEL_INTEGRITY: enforce" in text
    assert "pip install -r" not in text


# ---- Dockerfiles ---------------------------------------------------------------------------------------------------------------------

DOCKERFILES = ["Dockerfile", "Dockerfile.render"]


@pytest.mark.parametrize("name", DOCKERFILES)
def test_dockerfile_base_is_pinned_by_digest(name):
    text = (REPO / name).read_text(encoding="utf-8")
    assert re.search(r"^FROM python:3\.12-slim@sha256:[0-9a-f]{64}\s*$", text, re.M), name


def test_both_dockerfiles_use_the_same_base_digest():
    digests = {re.search(r"@(sha256:[0-9a-f]{64})", (REPO / n).read_text(encoding="utf-8")).group(1) for n in DOCKERFILES}
    assert len(digests) == 1, "Dependabot may only update Dockerfile; keep Dockerfile.render's digest in step"


@pytest.mark.parametrize("name,lock", [("Dockerfile", "requirements.lock"), ("Dockerfile.render", "requirements-render.lock")])
def test_dockerfile_installs_only_from_its_hash_locked_file(name, lock):
    text = (REPO / name).read_text(encoding="utf-8")
    assert f"pip install --require-hashes --no-deps -r {lock}" in text
    assert not re.search(r"pip install(?! --require-hashes)[^\n]*-r requirements", text)


@pytest.mark.parametrize("name", DOCKERFILES)
def test_dockerfile_runs_unprivileged_with_integrity_enforced(name):
    text = (REPO / name).read_text(encoding="utf-8")
    users = re.findall(r"^USER\s+(\S+)", text, re.M)
    assert users and users[-1] not in ("root", "0"), users
    assert "MODEL_INTEGRITY=enforce" in text and "HEALTHCHECK" in text


@pytest.mark.parametrize("name", DOCKERFILES)
def test_dockerfile_has_no_remote_shell_pipes_or_remote_add(name):
    text = (REPO / name).read_text(encoding="utf-8")
    assert not re.search(r"curl[^\n]*\|\s*(ba)?sh|wget[^\n]*\|\s*(ba)?sh|^ADD\s+https?://", text, re.M)


def test_the_render_image_is_torch_free_and_the_context_excludes_generated_and_secret_paths():
    assert "torch" not in (REPO / "requirements-render.lock").read_text(encoding="utf-8").lower().replace("# via", "")
    ignore = (REPO / ".dockerignore").read_text(encoding="utf-8")
    for needle in (".venv*/", "logs/", "reports/", "redteam/", ".git/"):
        assert needle in ignore, needle


# ---- lock files ---------------------------------------------------------------------------------------------------------------------

LOCKS = {"requirements-render.lock": "requirements-render.txt", "requirements.lock": "requirements.txt", "requirements-ci.lock": "requirements-ci.txt"}


def lock_packages(path):
    """{name: number of hashes} for every `name==version \\` line."""
    out, current = {}, None
    for line in path.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^([A-Za-z0-9_.-]+)==\S+", line)
        if m:
            current = m.group(1).lower().replace("_", "-")
            out[current] = 0
        elif current and "--hash=sha256:" in line:
            out[current] += 1
    return out


@pytest.mark.parametrize("lock", LOCKS)
def test_every_locked_package_is_exactly_pinned_and_has_hashes(lock):
    pkgs = lock_packages(REPO / lock)
    assert len(pkgs) > 15
    assert [p for p, n in pkgs.items() if n == 0] == []


@pytest.mark.parametrize("lock,source", LOCKS.items())
def test_each_lock_covers_the_requirements_it_was_compiled_from(lock, source):
    pkgs = lock_packages(REPO / lock)
    for line in (REPO / source).read_text(encoding="utf-8").splitlines():
        m = re.match(r"^([A-Za-z0-9_.-]+)", line.strip())
        if m and not line.strip().startswith("#"):
            assert m.group(1).lower().replace("_", "-") in pkgs, f"{m.group(1)} is in {source} but not in {lock}: run scripts/update_locks.sh"


def test_no_lock_file_contains_an_index_or_direct_url_override():
    for lock in LOCKS:
        text = (REPO / lock).read_text(encoding="utf-8")
        assert "--index-url" not in text and "--extra-index-url" not in text and " @ http" not in text


def test_the_security_documents_exist():
    assert (REPO / "SECURITY.md").exists() and (REPO / "docs" / "security-scans.md").exists()
