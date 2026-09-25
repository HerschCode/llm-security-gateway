#!/usr/bin/env bash
# Regenerate the hash-pinned lock files (Linux / Python 3.12: what CI and the Docker images run).
# Needs uv:  pip install uv        Review the diff: a lock change is a supply-chain change.
set -euo pipefail
cd "$(dirname "$0")/.."
for name in requirements-render requirements requirements-ci; do
  lock="${name}.lock"; [ "$name" = "requirements" ] && lock="requirements.lock"
  uv pip compile "${name}.txt" --python-version 3.12 --python-platform x86_64-manylinux_2_28 \
     --generate-hashes --no-header --annotation-style line -o "$lock"
done
echo "locks regenerated; verify with: pip download --no-deps --require-hashes -r requirements-render.lock -d /tmp/w (Linux, Python 3.12)"
