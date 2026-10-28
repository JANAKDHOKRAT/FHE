#!/usr/bin/env python3
"""Validate recorded artifacts before producing a human-readable study report."""
import argparse
import hashlib
import json
from pathlib import Path
import statistics


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def summarize(root):
    manifest = json.loads((root / 'manifest.json').read_text())
    if manifest['status'] not in ('completed', 'completed_with_rejections'):
        raise ValueError('study has not completed; do not generate a success report')
    rows = []
    for name, profile in manifest['profiles'].items():
        directory = root / name
        for result in profile['commands']:
            if sha(directory / result['log']) != result['log_sha256']:
                raise ValueError(f'{name}: qualification/build log changed')
        inventory = directory / 'source-sha256.json'
        if sha(inventory) != profile['source_inventory_sha256']:
            raise ValueError(f'{name}: inventory changed')
        if not profile['qualified']:
            rows.append(f'| {name} | Rejected at {profile.get("rejected_at", "qualification")} | — | — | — | — | — |')
            continue
        runs = [r for r in manifest['runs'] if r['profile'] == name]
        if len(runs) != manifest['processes_per_profile']:
            raise ValueError(f'{name}: missing independent setup')
        samples = []
        for run in runs:
            sample = directory / f'count-exact-{run["repeat"]}.json'
            log = directory / run['log']
            if sha(sample) != run['sample_sha256'] or sha(log) != run['log_sha256']:
                raise ValueError(f'{name}: measurement or log changed')
            d = json.loads(sample.read_text())
            if len(d['evaluator_total_per_batch_ms']) != manifest['batches_per_process']:
                raise ValueError('missing batch times')
            if log.read_text().count(' verified: evaluator ') != manifest['batches_per_process']:
                raise ValueError('missing decrypted batch checks')
            samples.append(d)
        def span(key, scale=1):
            values = [d[key] / scale for d in samples]
            return f'{min(values):.3f}–{max(values):.3f}'
        timing = [statistics.median(d['evaluator_total_per_batch_ms']) / 4000 for d in samples]
        allkeys = [(d['rotation_key_bytes'] + d['eval_mult_key_bytes']) / 2**30 for d in samples]
        rows.append(f'| {name} | Qualified on recorded tests | {span("report_bytes", 2**20)} | '
                    f'{min(allkeys):.3f}–{max(allkeys):.3f} | {span("setup_ms", 1000)} | '
                    f'{span("peak_rss_kb", 2**20)} | {min(timing):.3f}–{max(timing):.3f} |')
    return '\n'.join([
        '# Count exact: multiparty-mode parameter ablation', '',
        'Actual encrypted circuit results, not a production-security certification. '
        'p=786433; OpenFHE nominal HEStd_128_classic; four reports per batch. '
        'Ranges below are across independent key setups, not confidence intervals.', '',
        '| Profile | Qualification | Ciphertext MiB | All evaluation keys GiB | Setup s | Whole-process peak GiB | Evaluator median s/report |',
        '|---|---|---:|---:|---:|---:|---:|', *rows, '',
        'All evaluation keys means serialized rotation plus multiplication keys; '
        'public keys are separate in raw JSON. Memory includes all simulated roles. '
        'Setup and evaluator medians have different boundaries; whole-process wall '
        'time, client and collector timings remain in raw JSON.', '',
        'The direct default-mode candidate must not be recommended if qualification '
        'fails. Adding context headroom preserves the rebuild guard, but neither '
        'that nor passing tests proves equal multiparty security or minimal safe parameters. '
        'No warm-up or network deployment is measured. See README.md for scope.', ''])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    report = summarize(args.directory)
    (args.directory / 'summary.md').write_text(report)
    print(report)
