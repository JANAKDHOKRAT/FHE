import csv
import json
from pathlib import Path

root = Path(__file__).resolve().parent
paper = {
    10: (9.562, 2.912, 82261, 0.024, 0.075),
    25: (24.891, 7.351, 205621, 0.027, 0.079),
    50: (48.888, 14.692, 411221, 0.045, 0.082),
    100: (99.750, 29.246, 822421, 0.052, 0.102),
}
rows = []
for length, (client, evaluator, payload, prio_client, prio_evaluator) in paper.items():
    path = root / f'sumvec-{length}.json'
    if not path.exists():
        continue
    d = json.loads(path.read_text())
    assert d['check'] == 'randomised' and d['type'] == f'sumvec:{length}:1'
    assert d['reports_per_batch'] == 4 and d['batches'] == 6
    assert len(d['evaluator_total_per_batch_ms']) == 6
    times = d['evaluator_total_per_report']
    rows.append({
        'length': length,
        'paper_boolean_client_ms_per_report': client,
        'cloud_bgv_client_median_ms_per_report': d['client_encrypt_per_report']['median_ms'],
        'paper_boolean_evaluator_s_per_report': evaluator,
        'cloud_bgv_evaluator_median_s_per_report': times['median_ms'] / 1000,
        'cloud_bgv_evaluator_min_s_per_report': min(d['evaluator_total_per_batch_ms']) / 4000,
        'cloud_bgv_evaluator_max_s_per_report': max(d['evaluator_total_per_batch_ms']) / 4000,
        'paper_boolean_report_bytes': payload,
        'cloud_bgv_ciphertext_bytes': d['report_bytes'],
        'cloud_bgv_serialized_report_bytes': d['serialized_report_bytes'],
        'paper_prio3_client_ms_per_report': prio_client,
        'paper_prio3_evaluator_ms_per_report': prio_evaluator,
        'cloud_bgv_collector_median_ms_per_batch': d['collector_decrypt_per_batch']['median_ms'],
        'cloud_bgv_setup_ms': d['setup_ms'],
        'cloud_bgv_peak_rss_kb': d['peak_rss_kb'],
    })
assert rows, 'No completed results'
with (root / 'comparison.csv').open('w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
lines = [
    '# SumVec: paper Boolean baseline and cloud prime-field BGV measurements',
    '',
    f'Completed: {len(rows)}/4 lengths. Each completed cloud configuration verified six batches of four reports against the plaintext result.',
    '',
    '| Vector length | Paper Boolean evaluator, s/report | Cloud BGV evaluator median, s/report | Cloud observed range, s/report | Paper payload, decimal kB | Cloud ciphertext payload, decimal kB |',
    '|---:|---:|---:|---:|---:|---:|',
]
for r in rows:
    lines.append(f"| {r['length']} | {r['paper_boolean_evaluator_s_per_report']:.3f} | {r['cloud_bgv_evaluator_median_s_per_report']:.3f} | {r['cloud_bgv_evaluator_min_s_per_report']:.3f}–{r['cloud_bgv_evaluator_max_s_per_report']:.3f} | {r['paper_boolean_report_bytes']/1000:.3f} | {r['cloud_bgv_ciphertext_bytes']/1000:.3f} |")
lines += [
    '',
    '## Interpretation and limits',
    '',
    '- These are observations from different implementations on different machines, not a controlled speedup comparison. The paper uses Apple M2 Max, Apple Clang 17, OpenFHE 1.4.2 BinFHE STD128/GINX with OpenMP off. The cloud uses Intel Xeon Platinum 8573C, GCC 14.2, Rust 1.94.1, OpenFHE 1.3.1 BGV with OMP_NUM_THREADS=2. Raw JSON includes machine and loaded-library metadata.',
    '- The cloud implements the paper architecture: one evaluator, one collector holding the secret key. It uses p=786433, ring dimension 65536, depth 28, and seven randomized residual checks. These are not Boolean gates and not exact deterministic validation. Exact mode cannot support every requested length under its current parameter cap.',
    '- Both use binary SumVec inputs with maximum one and four reports per batch. The cloud uses seeded random binary measurements; the paper alternates bits. Both evaluate fixed-shape circuits, but these are not identical input sequences.',
    '- Cloud evaluator totals sum the measured admission, validation/decoding, and finish calls within each batch. Divide each batch total by four, then take the median. Do not add medians of the separate stages. Admission includes ciphertext parsing, rebuilding and group masking. Setup, evaluator construction/key installation, external message serialization, client encryption and collector decryption are outside these totals. The paper has its own stated stage boundaries, so remaining differences must accompany any comparison.',
    '- Six batch totals are stored in evaluator_total_per_batch_ms. The reported confidence intervals use binomial order-statistic ranks; their population coverage relies on suitable sampling assumptions, which shared keys and sequential execution do not establish automatically. Observed ranges are shown above without assuming independent samples.',
    '- Cloud payload columns report the packed ciphertext only; serialized_report_bytes also includes the report envelope. The paper counts its serialized ciphertext vector. The CSV preserves both cloud size metrics. Payload differences reflect parameters, codecs and algorithms rather than CPU speed, but they are not an equal-security size theorem.',
    '- Successful output checks establish correctness on these generated valid inputs, not security against arbitrary malformed ciphertexts. Separate encrypted integration tests covered selected invalid encodings and cancellation pairs.',
    '- A same-machine rerun of both programs is the preferred timing comparison. The supplied rerun.sh builds and runs the harness on Linux with Rust and the pinned OpenFHE 1.3.1 already configured. Native macOS needs build support first: the existing wrapper version gate checks Linux .so paths. Do not remove its version checks as a shortcut.',
    '- No professor Boolean driver or raw logs were supplied. The paper baseline columns are transcribed observations, not locally reproduced measurements. No historical paper result was overwritten.',
    '',
    '## Reproduction',
    '',
    'See rerun.sh for the four commands. run-metadata.json records the executable SHA-256 and base commit; source.patch.gz records the local dispatch fix and timing instrumentation. Per-length JSON and logs contain the outputs and successful batch messages. These files record cloud-instance validation, not a local reproduction of the paper Boolean baseline.',
]
(root / 'comparison.md').write_text('\n'.join(lines) + '\n')
print(f'Wrote comparison.csv and comparison.md: {len(rows)}/4 complete')
