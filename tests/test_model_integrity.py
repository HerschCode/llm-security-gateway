"""Model artifact integrity (gateway/model_integrity.py): a tampered pickle is refused before it is deserialized."""
import hashlib
import pickle
import warnings

import pytest

from gateway import model_integrity as mi


@pytest.fixture
def fake_repo(tmp_path, monkeypatch):
    """A repo root with models/ and a manifest, wired into the module."""
    models = tmp_path / "models" / "thing"
    models.mkdir(parents=True)
    monkeypatch.setattr(mi, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(mi, "MODELS_DIR", tmp_path / "models")
    monkeypatch.setattr(mi, "MANIFEST", tmp_path / "models" / "MANIFEST.sha256")
    artifact = models / "index.pkl"
    artifact.write_bytes(pickle.dumps({"ids": [1, 2, 3]}))
    mi.write_manifest(["models/thing/index.pkl"])
    return tmp_path, artifact


# ---- the shipped manifest ---------------------------------------------------------------------------------------------------------

def test_the_shipped_manifest_matches_the_shipped_artifacts():
    """If this fails you changed a model artifact without updating the manifest: run `python -m scripts.update_model_manifest` and commit both."""
    manifest = mi.load_manifest()
    assert set(manifest) == {rel for rel in mi.SERVED_ARTIFACTS if (mi.REPO_ROOT / rel).exists()}
    for rel, digest in manifest.items():
        assert mi.sha256_file(mi.REPO_ROOT / rel) == digest, rel


def test_the_manifest_is_sha256sum_compatible():
    for line in mi.MANIFEST.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            digest, sep, rel = line.partition("  ")
            assert sep == "  " and len(digest) == 64 and int(digest, 16) >= 0 and rel.startswith("models/")


def test_every_pickle_the_repository_ships_under_models_is_covered_by_the_manifest():
    """A new .pkl added under models/ must be listed (or be deliberately not loaded by the gateway)."""
    listed = set(mi.load_manifest())
    served_pickles = {p.relative_to(mi.REPO_ROOT).as_posix() for p in (mi.MODELS_DIR).rglob("*.pkl")}
    uncovered = sorted(p for p in served_pickles if p not in listed)
    # student.pkl is a distillation experiment loaded by no gateway code; the two loaders' pickles must all be listed
    assert set(uncovered) <= {"models/student.pkl"}


def test_the_real_detectors_load_their_artifacts_under_enforce(monkeypatch):
    monkeypatch.setenv("MODEL_INTEGRITY", "enforce")
    from gateway.detectors.classifier_numpy import ScratchClassifierDetectorNumpy
    from gateway.detectors.embedding_similarity import EmbeddingSimilarityDetector
    ScratchClassifierDetectorNumpy().load()
    EmbeddingSimilarityDetector().load()


# ---- verify() ------------------------------------------------------------------------------------------------------------------

def test_an_unchanged_artifact_verifies(fake_repo):
    _, artifact = fake_repo
    assert mi.verify(artifact) == "ok"


def test_a_modified_artifact_is_refused_in_enforce_mode(fake_repo, monkeypatch):
    _, artifact = fake_repo
    artifact.write_bytes(pickle.dumps({"ids": [1, 2, 3, 4]}))
    monkeypatch.setenv("MODEL_INTEGRITY", "enforce")
    with pytest.raises(mi.ModelIntegrityError, match="does not match"):
        mi.verify(artifact)


def test_an_artifact_missing_from_the_manifest_is_refused_in_enforce_mode(fake_repo, monkeypatch):
    tmp_path, _ = fake_repo
    extra = tmp_path / "models" / "thing" / "other.pkl"
    extra.write_bytes(b"x")
    monkeypatch.setenv("MODEL_INTEGRITY", "enforce")
    with pytest.raises(mi.ModelIntegrityError, match="not in"):
        mi.verify(extra)


def test_warn_mode_is_the_default_and_warns_instead_of_raising(fake_repo, monkeypatch):
    _, artifact = fake_repo
    artifact.write_bytes(b"tampered")
    monkeypatch.delenv("MODEL_INTEGRITY", raising=False)
    with pytest.warns(RuntimeWarning, match="MODEL_INTEGRITY=warn"):
        assert mi.verify(artifact) == "mismatch"


def test_off_mode_does_not_look(fake_repo, monkeypatch):
    _, artifact = fake_repo
    artifact.write_bytes(b"tampered")
    monkeypatch.setenv("MODEL_INTEGRITY", "off")
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert mi.verify(artifact) == "skipped"


def test_a_path_outside_models_is_not_covered_and_is_skipped(fake_repo, tmp_path_factory, monkeypatch):
    elsewhere = tmp_path_factory.mktemp("scratch") / "x.pkl"
    elsewhere.write_bytes(b"anything")
    monkeypatch.setenv("MODEL_INTEGRITY", "enforce")
    assert mi.verify(elsewhere) == "skipped"


def test_a_missing_manifest_is_treated_as_every_artifact_unlisted(fake_repo, monkeypatch):
    _, artifact = fake_repo
    mi.MANIFEST.unlink()
    monkeypatch.setenv("MODEL_INTEGRITY", "enforce")
    with pytest.raises(mi.ModelIntegrityError):
        mi.verify(artifact)


def test_invalid_mode_is_rejected(monkeypatch):
    monkeypatch.setenv("MODEL_INTEGRITY", "maybe")
    with pytest.raises(ValueError):
        mi.mode()


def test_sha256_file_matches_hashlib_on_a_large_file(tmp_path):
    p = tmp_path / "big.bin"
    data = b"abc" * 1_000_000
    p.write_bytes(data)
    assert mi.sha256_file(p) == hashlib.sha256(data).hexdigest()


# ---- the tampered-pickle story, end to end -------------------------------------------------------------------------------------

def test_a_tampered_pickle_is_never_deserialized(fake_repo, monkeypatch, tmp_path):
    """A pickle can run code on load. Under enforce, the loader must refuse it BEFORE unpickling."""
    _, artifact = fake_repo
    marker = tmp_path / "pwned.txt"

    class Evil:
        def __reduce__(self):
            return (open, (str(marker), "w"))                           # what a hostile pickle would do on load

    artifact.write_bytes(pickle.dumps(Evil()))
    monkeypatch.setenv("MODEL_INTEGRITY", "enforce")
    with pytest.raises(mi.ModelIntegrityError):
        mi.verify(artifact)                                             # the loaders call this first
    assert not marker.exists()
