"""Finish the selected slow qualification without converting partial runs to passes.

This consumes the selected vector100-late logs; it does not launch/restart FHE,
alter raw logs, commit, push, or declare production security.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--watch', action='store_true')
    parser.add_argument('--fixture-dir', type=Path, required=True)
    parser.add_argument('--inspector', type=Path, required=True)
    args = parser.parse_args()
    process_file = ROOT / 'prime-diagnostic/vector100-late.process.json'
    deadline = time.monotonic() + 6 * 60 * 60
    process = None
    while process is None:
        try:
            process = json.loads(process_file.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            # The frozen wrapper writes this small file at exit. A watcher may
            # briefly see its creation before its JSON write has finished.
            if not args.watch:
                raise SystemExit('Selected encrypted process has not finished')
            if time.monotonic() >= deadline:
                raise SystemExit('Watch expired; no success inferred')
            time.sleep(5)
    log = ROOT / 'prime-diagnostic/vector100-late.jsonl'
    native = [json.loads(line) for line in log.read_text().splitlines()]
    if process['returncode'] != 0 or not native or native[-1]['status'] != 'EXPLORATORY_TASK_PASS':
        raise SystemExit('Selected native qualification failed or is incomplete; raw records preserved')
    # No secret-key file should be included in these synthetic public fixtures.
    expected = {'public_key.bin', 'report.bin', 'aggregate.bin'}
    assert {p.name for p in args.fixture_dir.iterdir()} == expected
    environment = dict(os.environ)
    environment['LD_LIBRARY_PATH'] = '/workspace/fhe-deps/install-1.4.2/lib'
    with (ROOT / 'evidence/rust-final-codec.jsonl').open('w') as out:
        with (ROOT / 'evidence/rust-final-codec.stderr').open('w') as err:
            codec = subprocess.run([
                str(args.inspector), str(ROOT / 'prime-diagnostic/context100-fast.jsonl'),
                str(args.fixture_dir), '--require-aggregate'
            ], stdout=out, stderr=err, env=environment)
    assert codec.returncode == 0, 'Independent Rust aggregate codec check failed'
    verified = subprocess.run([sys.executable, str(ROOT / 'summarize.py'), '--require-all'],
                              capture_output=True, text=True)
    (ROOT / 'evidence/qualification.stderr').write_text(verified.stderr)
    assert verified.returncode == 0, verified.stderr
    summary = json.loads(verified.stdout)
    (ROOT / 'evidence/qualification.json').write_text(json.dumps(summary, indent=2) + '\n')
    fixtures = {
        p.name: {'bytes': p.stat().st_size, 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
        for p in sorted(args.fixture_dir.iterdir())
    }
    (ROOT / 'evidence/public-fixtures.json').write_text(json.dumps({
        'scope': 'Synthetic test data, public key and ciphertexts only; no secret key saved',
        'directory': str(args.fixture_dir), 'files': fixtures
    }, indent=2) + '\n')
    lines = [
        '# Selected original-encoding results', '',
        'Generated only after all eight selected native cases and the final',
        'length-100 Rust aggregate inspection passed. These are finite',
        'correctness results; the production-security gate remains NOT GREEN.', '',
        'All cases use p=65,537 and ring dimension32,768. Sum uses the original',
        'seven weighted bits, vectors use individual bits, and histograms use',
        'one-hot vectors. Unused slots remain ignored. Profiles differ by task.', '',
        '| Task | Client report bytes | Evaluation-key bytes | Reports | Slot checks |',
        '|---|---:|---:|---:|---:|'
    ]
    for case in summary['cases']:
        label = f"{case['task']} ({case['length']} encoded coordinates)"
        lines.append(f"| {label} | {case['report_bytes']:,} | {case['evaluation_key_bytes']:,} | {case['reports']} | {case['slot_checks']} |")
    last = summary['cases'][-1]
    lines += ['', f"Length100 emits {last['aggregate_ciphertexts']} final ciphertext,",
              f"measured as {last['aggregate_wire_bytes']:,} collector-output bytes.", '',
              'The length100 case uses the documented isolated OpenFHE prime-selector',
              'patch. The other rows use stock OpenFHE1.4.2; Histogram8 is a retained',
              'earlier run. No new matched runtime or peak-memory comparison is claimed.', '',
              'Several uploads exceed their corresponding published lookup references. Evaluation',
              'keys are below the selected corresponding lookup references. This is',
              'a trade-off, not a universal report-size or performance win.', '',
              'The library128-bit target is enabled, but independent attack estimates',
              'must be disclosed. In particular, recorded length100 primal-uSVP estimates',
              'are about92.86 ADPS16 bits and126.10 MATZOV bits, not a128-bit certification.',
              'Arbitrary-ciphertext robustness, collector circuit privacy and a complete',
              'negligible-decryption-failure argument remain unresolved.', '',
              'Raw evidence and hashes: evidence/qualification.json and',
              'evidence/public-fixtures.json. See README.md and REPRODUCE.md.']
    (ROOT / 'RESULTS.md').write_text('\n'.join(lines) + '\n')
    print(json.dumps({'status': 'SELECTED_FINITE_QUALIFICATION_AND_CODEC_PASS',
                      'cases': len(summary['cases']),
                      'production_security_gate': 'NOT GREEN',
                      'raw_legacy_wrapper_record_preserved': True}))


if __name__ == '__main__':
    main()
