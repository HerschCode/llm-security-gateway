"""
Exports the trained scratch classifier's weights from torch's state_dict format
into a plain .npz (numpy) file, so the SERVING path
(gateway/detectors/classifier_numpy.py) never needs to import torch.

Why this exists: torch is the single heaviest dependency in this repo (the
reason "full mode" -- all 3 detection layers -- didn't fit Render's 512MB free
tier, see docs/decisions.md's GATEWAY_LITE entry). The model itself is tiny
(embedding(8000, 64) + Linear(64,32) + Linear(32,1) -- see
scratch_classifier_model.py) -- there's no real reason its FORWARD PASS at
inference time needs a 700MB deep-learning framework. torch is still required
for TRAINING (scripts/train_scratch_classifier.py's autograd, optimizer, data
loader) -- this script is the one-time bridge from "trained with torch" to
"served with numpy," run after training, not instead of it.

Usage:
    python scripts/export_classifier_to_numpy.py
"""
from pathlib import Path

import numpy as np
import torch

REPO_ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = REPO_ROOT / "models" / "scratch_classifier"


def export(model_dir: Path = MODEL_DIR):
    state_dict = torch.load(model_dir / "model.pt", map_location="cpu", weights_only=True)
    weights = {k: v.numpy() for k, v in state_dict.items()}
    expected = {"embedding.weight", "fc1.weight", "fc1.bias", "fc2.weight", "fc2.bias"}
    missing = expected - set(weights)
    if missing:
        raise ValueError(
            f"state_dict is missing {missing} -- scratch_classifier_model.py's "
            "architecture changed without updating this export script's assumptions."
        )
    out_path = model_dir / "weights.npz"
    np.savez(out_path, **weights)
    print(f"Exported {len(weights)} arrays to {out_path} "
          f"({sum(a.nbytes for a in weights.values()) / 1024:.1f} KB)")


if __name__ == "__main__":
    export()
    # Also export the "before the RNG-seeding fix" snapshot if it exists, purely
    # so docs/decisions.md's before/after story stays inspectable without torch.
    before_dir = REPO_ROOT / "models" / "scratch_classifier_before_fix"
    if (before_dir / "model.pt").exists():
        export(before_dir)
