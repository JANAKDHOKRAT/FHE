"""Check publication files and public fixture hashes; no FHE/security proof."""
from pathlib import Path
import hashlib,json

ROOT=Path(__file__).resolve().parent
manifest=json.loads((ROOT/'PACKAGE-SHA256.json').read_text())
for name,expected in manifest.items():
    p=ROOT/name
    assert p.is_file() and not p.is_symlink(),name
    assert hashlib.sha256(p.read_bytes()).hexdigest()==expected,name
expected=json.loads((ROOT/'evidence/public-fixtures.json').read_text())['files']
assert {p.name for p in (ROOT/'public-fixtures').iterdir()}==set(expected)
for name,item in expected.items():
    p=ROOT/'public-fixtures'/name
    assert p.stat().st_size==item['bytes']
    assert hashlib.sha256(p.read_bytes()).hexdigest()==item['sha256']
print(json.dumps({'status':'PACKAGE_INTEGRITY_PASS','files':len(manifest),
                  'public_fixture_files':len(expected),'production_security_certified':False}))
