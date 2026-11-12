"""Download the pinned public EVTX samples used by the real-telemetry tests.

Dataset: https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES (GPL-3.0).
The samples are NOT redistributed in this repository. They are fetched from upstream at a pinned
commit and verified by SHA-256, so the tests are reproducible and tamper-evident.
"""
from __future__ import annotations

import hashlib
import sys
import urllib.parse
import urllib.request

from tools.common import SAMPLES_CACHE, load_manifest


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    manifest = load_manifest()
    repo, commit = manifest["dataset"]["repo"], manifest["dataset"]["commit"]
    failures = 0
    for sample in manifest["samples"]:
        dest = SAMPLES_CACHE / sample["path"]
        if dest.exists() and _sha256(dest.read_bytes()) == sample["sha256"]:
            continue
        url = f"https://raw.githubusercontent.com/{repo}/{commit}/" + urllib.parse.quote(sample["path"])
        data = urllib.request.urlopen(url, timeout=60).read()
        if _sha256(data) != sample["sha256"]:
            print(f"HASH MISMATCH: {sample['path']}", file=sys.stderr)
            failures += 1
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        print(f"fetched {sample['path']}")
    print(f"{len(manifest['samples']) - failures}/{len(manifest['samples'])} samples ready in {SAMPLES_CACHE}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
