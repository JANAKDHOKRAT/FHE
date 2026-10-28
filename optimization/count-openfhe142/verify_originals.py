from pathlib import Path
import hashlib,json,re
root=Path(__file__).resolve().parent
base=json.loads((root/'BASELINE-SHA256.json').read_text())
allowed={'openfhe-tbgv-rs/build.rs','openfhe-tbgv-rs/tests/key_noise_gap.rs','openfhe-tbgv-rs/tests/crs_ceremony.rs'}
changed=[]
for rel,h in base.items():
 original=root.parent/'count'/rel
 assert original.is_file()and hashlib.sha256(original.read_bytes()).hexdigest()==h, f'Original changed: {rel}'
 if hashlib.sha256((root/rel).read_bytes()).hexdigest()!=h:changed.append(rel)
assert set(changed)==allowed, changed
print(f'PASS: {len(base)} original files preserved; only expected three copied-file changes')

for name in ['key_noise_gap.rs','crs_ceremony.rs']:
 old=(root.parent/'count'/'openfhe-tbgv-rs/tests'/name).read_text()
 expected,n=re.subn(r'(#\[test\]\nfn [a-zA-Z0-9_]+\(\) \{\n)',r'\1    let _serial = serial();\n',old)
 expected+="\n// Context/key creation mutates OpenFHE process-global tables; see ContextInner contract.\nfn serial() -> std::sync::MutexGuard<'static, ()> {\n    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());\n    SERIAL.lock().unwrap_or_else(|e| e.into_inner())\n}\n"
 assert n==2 and expected==(root/'openfhe-tbgv-rs/tests'/name).read_text(), name
old=(root.parent/'count/openfhe-tbgv-rs/build.rs').read_text()
assert (root/'openfhe-tbgv-rs/build.rs').read_text()==old.replace('&["1.3.1"];','&["1.3.1", "1.4.2"];')
print('PASS: original test assertions retained byte-for-byte; only exact mutex additions and SDK entry')
