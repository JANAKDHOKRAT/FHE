#!/usr/bin/env python3
"""Read-only verification of baseline sources and archived evidence."""
from pathlib import Path
import hashlib,json
here=Path(__file__).resolve().parent
repo=here.parents[1]
def check(root,inventory):
 bad=[]
 for name,want in json.loads(inventory.read_text()).items():
  p=root/name
  if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest()!=want:bad.append(name)
 if bad:raise SystemExit('BASELINE DIFFERENCES: '+', '.join(bad))
 return len(json.loads(inventory.read_text()))
a=check(repo,here/'baseline-sha256.json')
b=check(here,here/'baseline-evidence-sha256.json')
print(f'PASS: {a} original files unchanged; {b} preserved evidence files match hashes')
