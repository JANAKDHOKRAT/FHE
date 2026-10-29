#!/usr/bin/env python3
"""Integrity and historical evidence checks; does not rerun encrypted circuits."""
import hashlib
import json
import pathlib
import subprocess
import sys

root = pathlib.Path(__file__).resolve().parent
manifest = json.loads((root / 'PACKAGE-SHA256.json').read_text())
for name, digest in manifest.items():
    path = pathlib.Path(name)
    assert not path.is_absolute() and '..' not in path.parts, name
    assert hashlib.sha256((root / path).read_bytes()).hexdigest() == digest, name
subprocess.run([sys.executable, str(root / 'full-cost142/audit/verify_claims.py')], check=True)
print('PACKAGE_INTEGRITY_AND_RECORDED_EVIDENCE_PASS')
