"""
Integrity check for the model artifacts the gateway loads.

Why: `pickle.load` runs code chosen by whoever wrote the file (Bandit B301), and the layer-2 vectorizer and known-bad index are pickles. The
files are the repo's own, but "the repo's own" is exactly what a tampered checkout, a poisoned build cache or a swapped volume is not. Before an
artifact is deserialized (or a served weight file is used) its SHA-256 is compared with `models/MANIFEST.sha256`, a plain `sha256sum` manifest that
is committed and checked in CI (tests/test_model_integrity.py), so changing an artifact without updating the manifest is a visible diff.

    MODEL_INTEGRITY=enforce   a mismatch or an artifact missing from the manifest raises ModelIntegrityError (set in Dockerfile.render)
    MODEL_INTEGRITY=warn      (default) the same condition emits a warning and loading continues: retraining and local experiments keep working
    MODEL_INTEGRITY=off       no check

Only files under the repository's models/ directory are checked; a path anywhere else (a temp directory in a test) is not covered by the
manifest and is skipped. After retraining, regenerate the manifest: `python -m scripts.update_model_manifest`.

What this does and does not do: it detects a changed file, not a malicious one. It does not authenticate WHO wrote the manifest (that is what
review of the commit that changes it is for), and it protects the loader, not the training pipeline.
"""
import hashlib
import os
import warnings
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MODELS_DIR = REPO_ROOT / "models"
MANIFEST = MODELS_DIR / "MANIFEST.sha256"

# Everything the gateway (or an opt-in detector) loads at runtime.
SERVED_ARTIFACTS = [
    "models/embedding_similarity/vectorizer.pkl",
    "models/embedding_similarity/known_bad.pkl",
    "models/embedding_similarity_st/known_bad_ids.pkl",
    "models/embedding_similarity_st/known_bad_vectors.npy",
    "models/scratch_classifier/weights.npz",
    "models/scratch_classifier/vocab.json",
    "models/scratch_classifier/model.pt",
]


class ModelIntegrityError(RuntimeError):
    pass


def mode() -> str:
    m = os.environ.get("MODEL_INTEGRITY", "warn")
    if m not in ("enforce", "warn", "off"):
        raise ValueError(f"MODEL_INTEGRITY must be enforce, warn or off, got {m!r}")
    return m


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def load_manifest(manifest: Path | None = None) -> dict[str, str]:
    """{repo-relative posix path: sha256}, from `sha256sum`-format lines (`<hex>  <path>`)."""
    manifest = manifest or MANIFEST
    out = {}
    if manifest.exists():
        for line in manifest.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                digest, _, rel = line.partition("  ")
                out[rel.strip()] = digest.strip().lower()
    return out


def _relative(path: Path) -> str | None:
    try:
        return path.resolve().relative_to(REPO_ROOT.resolve()).as_posix() if MODELS_DIR.resolve() in path.resolve().parents else None
    except ValueError:
        return None


def verify(path: Path) -> str:
    """Check one artifact before it is loaded. Returns "ok", "skipped", "unlisted" or "mismatch" (the last two raise in enforce mode)."""
    m = mode()
    if m == "off":
        return "skipped"
    rel = _relative(Path(path))
    if rel is None:
        return "skipped"                                        # outside models/: nothing in the manifest can cover it
    expected = load_manifest().get(rel)
    if expected is None:
        status, why = "unlisted", f"{rel} is not in {MANIFEST.relative_to(REPO_ROOT).as_posix()}"
    elif sha256_file(Path(path)) != expected:
        status, why = "mismatch", f"{rel} does not match its recorded SHA-256 (modified since the manifest was written)"
    else:
        return "ok"
    if m == "enforce":
        raise ModelIntegrityError(why + "; refusing to load it. If the change is intended, run: python -m scripts.update_model_manifest")
    warnings.warn(why + " (MODEL_INTEGRITY=warn); set MODEL_INTEGRITY=enforce in production", RuntimeWarning, stacklevel=3)
    return status


def write_manifest(paths=SERVED_ARTIFACTS, manifest: Path | None = None) -> dict[str, str]:
    manifest = manifest or MANIFEST
    entries = {rel: sha256_file(REPO_ROOT / rel) for rel in paths if (REPO_ROOT / rel).exists()}
    lines = ["# SHA-256 of the model artifacts the gateway loads (sha256sum format: run `sha256sum -c --ignore-missing models/MANIFEST.sha256` from the repo root).",
             "# Regenerate with: python -m scripts.update_model_manifest   (see gateway/model_integrity.py)"]
    lines += [f"{digest}  {rel}" for rel, digest in sorted(entries.items())]
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return entries
