import csv
import json
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parent
metadata_path = root / 'matrix-metadata.json'
meta = json.loads(metadata_path.read_text()) if metadata_path.exists() else {'configurations': [
    ('exact', 'count', 24, 65536), ('exact', 'sum:100', 27, 65536),
    ('exact', 'histogram:8', 28, 65536), ('exact', 'sumvec:10:1', 28, 65536),
    ('randomised', 'count', 28, 65536), ('randomised', 'sum:100', 28, 65536),
    ('randomised', 'histogram:8', 28, 65536),
]}
rows = []
for mode, task, depth, ring in meta['configurations']:
    name = mode + '-' + task.replace(':', '-')
    path = root / f'{name}.json'
    if not path.exists():
        continue
    d = json.loads(path.read_text())
    assert (d['check'], d['type'], d['mult_depth'], d['ring_dim']) == (mode, task, depth, ring)
    assert len(d['evaluator_total_per_batch_ms']) == 6
    assert all(f'batch {b}/6 verified' in path.with_suffix('.log').read_text() for b in range(1, 7))
    rows.append({
        'task': task, 'check': mode, 'ring_dim': ring, 'depth': depth,
        'key_switch_digits': d['key_switch_digits'],
        'reports_per_batch': 4, 'batches': 6,
        'evaluator_median_s_per_report': d['evaluator_total_per_report']['median_ms'] / 1000,
        'evaluator_min_s_per_report': min(d['evaluator_total_per_batch_ms']) / 4000,
        'evaluator_max_s_per_report': max(d['evaluator_total_per_batch_ms']) / 4000,
        'client_median_ms_per_report': d['client_encrypt_per_report']['median_ms'],
        'collector_median_ms_per_batch': d['collector_decrypt_per_batch']['median_ms'],
        'ciphertext_bytes_per_report': d['report_bytes'],
        'serialized_report_bytes': d['serialized_report_bytes'],
        'rotation_key_bytes': d['rotation_key_bytes'],
        'multiplication_key_bytes': d['eval_mult_key_bytes'],
        'public_key_bytes': d['public_key_bytes'],
        'setup_ms': d['setup_ms'], 'peak_rss_kb': d['peak_rss_kb'],
        'configuration_wall_s': d['wall_s'],
        'configuration_wall_s_per_report_all_roles_and_setup': d['wall_s'] / 24,
    })
assert rows
with (root / 'summary.csv').open('w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator='\n')
    w.writeheader()
    w.writerows(rows)
lines = [
    '# Practical exact and randomized task measurements', '',
    f'Completed {len(rows)}/7 configurations, with six verified four-report batches per completed configuration.', '',
    '| Task | Check | Depth | Evaluator median s/report | Observed s/report range | Ciphertext MB/report | Rotation keys GiB |',
    '|---|---|---:|---:|---:|---:|---:|',
]
for r in rows:
    lines.append(f"| {r['task']} | {r['check']} | {r['depth']} | {r['evaluator_median_s_per_report']:.3f} | {r['evaluator_min_s_per_report']:.3f}–{r['evaluator_max_s_per_report']:.3f} | {r['ciphertext_bytes_per_report']/1e6:.3f} | {r['rotation_key_bytes']/2**30:.3f} |")
lines += [
    '', '## Scope and method', '',
    '- This matrix uses the unchanged depth-28 configuration limit from commit 686b8d3: prime p=786433, nominal HEStd_128_classic security, ring dimension 65536, OMP_NUM_THREADS=2, OpenFHE 1.3.1, GCC 14.2, Rust 1.94.1, cloud Xeon Platinum 8573C. Each JSON records the actual context and machine.',
    '- The paper roles use one collector key, but the reused OpenFHE wrapper retains its multiparty-capable context defaults, including NOISE_FLOODING_MULTIPARTY, FLEXIBLEAUTOEXT and UNIFORM_TERNARY. These measurements are not a demonstration of minimal single-key BGV parameters or optimal key size.',
    '- Count, Sum bounded by 100, and Histogram with eight buckets are measured with both exact and seven-repetition randomized validation. Exact binary SumVec is measured at length ten. Bounds and bucket count are explicit workload choices, not an exhaustive sweep of all possible task parameters.',
    '- Every measured batch must decrypt to the expected plaintext output before a configuration succeeds. These valid-input measurements are not a malicious-ciphertext security proof. Earlier encrypted integration tests exercised selected invalid encodings.',
    '- Evaluator totals sum timed admission, validation flushes and finish calls within each batch. Divide each batch total by four, then summarize. Setup, evaluator construction/key loading, message serialization, client encryption and collector decryption are outside the evaluator total and must not be silently treated as end-to-end latency.',
    '- The CSV also preserves total configuration wall time and that time divided by 24 reports. These include all roles, key loading, and setup in this serial local experiment; they are not network or deployed-DAP latency measurements.',
    '- Six sequential observations share a collection key. Observed ranges are reported; statistical confidence-interval coverage requires sampling assumptions not established by sequential execution alone. No controlled warm-up, affinity or external background-load control was used.',
    '- The rerun script targets the Linux build configured in CI. The current wrapper checks Linux .so library paths; native macOS requires a build adaptation before a same-M2 comparison.',
    '- Earlier randomized SumVec measurements at lengths 10, 25, 50 and 100 remain valid and are not overwritten or rerun here. These cloud results are not a controlled speed comparison with the paper Boolean results on an Apple M2 Max.',
    '', '## Exact validation limits and stopped larger-ring exploration', '',
    '- With the retained configuration, exact binary SumVec requires depths 28, 29, 30 and 31 for lengths 10, 25, 50 and 100. The executable refuses the latter three before setup; exact-limit-checks.json records those actual refusals. No six-batch timing result is claimed for them here.',
    '- This is a configuration frontier, not a proof of impossibility. A separate parameter probe found depth 29 can retain ring 65536 with six digits, while accepted depth-30/31 candidates used ring 131072. Some candidates were rejected by OpenFHE; none of those errors was bypassed.',
    '- A separate experimental depth-31 encrypted length-100 integration test passed, including valid inputs, a cancellation pair, the last packed group and a cross-group write. Its rotation keys were 6.41 GiB and setup took about 190 seconds. This was a functional test, not a completed six-batch benchmark.',
    '- At the user\'s direction the larger-ring benchmark was stopped, its experimental source was archived locally, and the core-library changes were reverted before this matrix. The larger-ring investigation does not appear as a successful timed configuration in this table.',
    '', '## Evidence', '',
    'Per-configuration JSON contains raw batch totals, stage summaries, sizes and machine metadata. Logs record six successful batch checks. matrix-metadata.json records the executable hash and base commit. verification.json records source and raw-file hashes. To rerun into a new directory, use bash rerun.sh OUTPUT_DIR, then python3 summarize.py OUTPUT_DIR. Set PAPER_CORE_CRATE_DIR when using the downloaded script outside this checkout. The original cloud runner is retained with the local experiment records.',
]
(root / 'summary.md').write_text('\n'.join(lines) + '\n')
print(f'Wrote summary: {len(rows)}/7 completed configurations')
