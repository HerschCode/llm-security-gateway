"""Regenerate models/MANIFEST.sha256 after retraining or replacing a model artifact (gateway/model_integrity.py).

Run: python -m scripts.update_model_manifest
Commit the manifest with the artifact change, so the diff shows both."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway import model_integrity  # noqa: E402


def main():
    entries = model_integrity.write_manifest()
    for rel, digest in entries.items():
        print(f"{digest}  {rel}")
    print(f"wrote {model_integrity.MANIFEST.relative_to(model_integrity.REPO_ROOT)} ({len(entries)} artifacts)")


if __name__ == "__main__":
    main()
