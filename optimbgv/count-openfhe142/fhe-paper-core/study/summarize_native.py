#!/usr/bin/env python3
"""Verify native study records before reporting any performance numbers."""
import argparse
import json
from pathlib import Path
import statistics
from run import digest


def summarize(root):
    m=json.loads((root/'manifest.json').read_text())
    if m['status'] not in ['completed','completed_with_rejections']:
        raise ValueError('study incomplete or failed; no success report')
    if not m.get('profiles') or not any(p.get('qualified') for p in m['profiles'].values()):
        raise ValueError('no qualified profiles')
    expected_names={name for name,p in m['profiles'].items() if p['qualified']}
    if {r['profile'] for r in m['runs']}!=expected_names:
        raise ValueError('timed and qualified profile sets differ')
    lines=['# Native single-key study: verified measurements','',
           'Real encrypted qualification and timings on one host. This is not production-security certification. '
           'The default threshold implementation is unchanged. Screening rows use one key/three batches; '
           'Count controls use two independent keys/six batches each. No confidence intervals are claimed.','',
           '| Profile | N | Depth | Ciphertext MiB | Evaluation keys GiB | Key setup API s | Process peak GiB | Evaluator median s/report |',
           '|---|---:|---:|---:|---:|---:|---:|---:|']
    data={};batches=reports=0
    for name,p in sorted(m['profiles'].items(),key=lambda item:(item[0]!='threshold-count',item[0])):
        q=p['qualification'];directory=root/name
        if digest(directory/q['log'])!=q['log_sha256']:raise ValueError('qualification log changed')
        if not p['qualified']:
            lines.append(f'| {name} | Rejected in qualification | — | — | — | — | — | — |');continue
        if q['returncode']!=0 or 'test result: ok. 1 passed; 0 failed' not in (directory/q['log']).read_text():
            raise ValueError('qualification success not established')
        runs=[r for r in m['runs'] if r['profile']==name]
        expected=2 if name in ['threshold-count','native-count-d3'] else 1
        if len(runs)!=expected:raise ValueError(f'{name}: incomplete independent setups')
        samples=[]
        for r in runs:
            file=directory/f'measurement-{r["repeat"]}.json'
            if r['returncode']!=0 or digest(file)!=r['measurement_sha256'] or digest(directory/r['log'])!=r['log_sha256']:
                raise ValueError('timing failed or changed')
            d=json.loads(file.read_text())
            if (d['type'],d['check'],d['reports_per_batch'],d['plain_mod'],d['security_bits'])!=(p['type'],p['mode'],p['reports'],786433,128):
                raise ValueError('configuration mismatch')
            if d['key_mode']!=('threshold-one-party' if p['digits'] is None else 'native-single'):raise ValueError('key mode mismatch')
            if p['digits'] is not None and d['key_switch_digits']!=p['digits']:raise ValueError('key digits mismatch')
            if p['groups'] is not None and d['reports_per_verification_ciphertext']!=p['groups']:raise ValueError('packing mismatch')
            if p['mode']=='randomised':
                if d['invalid_attempt_budget']!=1000000 or d['global_soundness_target_bits']!=128:raise ValueError('contract mismatch')
                if pow(d['plain_mod'],d['repetitions'])<d['invalid_attempt_budget']*(1<<d['global_soundness_target_bits']):raise ValueError('global soundness bound fails')
            expected_bytes=56+(2*d['ring_dim']*d['wire_residue_fixed_width_bits_per_coefficient']+7)//8
            if d['report_bytes']!=expected_bytes:raise ValueError('wire length does not match measured parameters')
            totals=d['evaluator_total_per_batch_ms']
            if len(totals)!=d['batches'] or (directory/r['log']).read_text().count(' verified: evaluator ')!=d['batches']:
                raise ValueError('missing decrypted batch checks')
            recomputed=statistics.median(totals)/d['reports_per_batch']
            if abs(recomputed-d['evaluator_total_per_report']['median_ms'])>0.00051:raise ValueError('incorrect timing summary')
            samples.append(d);batches+=d['batches'];reports+=d['batches']*d['reports_per_batch']
        def span(key,scale=1):
            values=[s[key]/scale for s in samples];lo=min(values);hi=max(values)
            return f'{lo:.3f}' if lo==hi else f'{lo:.3f}–{hi:.3f}'
        timing=[statistics.median(s['evaluator_total_per_batch_ms'])/s['reports_per_batch']/1000 for s in samples]
        keys=[(s['rotation_key_bytes']+s['eval_mult_key_bytes'])/2**30 for s in samples]
        def fmt(values):return f'{min(values):.3f}' if min(values)==max(values) else f'{min(values):.3f}–{max(values):.3f}'
        lines.append(f'| {name} | {p["reports"]} | {samples[0]["mult_depth"]} | {span("report_bytes",2**20)} | {fmt(keys)} | {span("setup_ms",1000)} | {span("peak_rss_kb",2**20)} | {fmt(timing)} |')
        data[name]=samples
    lines += ['',f'Verified timed batches: **{batches}**; reports: **{reports}**. Each recorded batch output matched its plaintext expectation.','',
              'Evaluation keys are serialized rotation plus multiplication keys. Public keys, context, outer report envelope, client/collector timings, raw batch samples and wall time are in the JSON. '
              'Native profile construction realizes a context before the setup timer; do not infer total setup speedup from that API stage. Whole-process wall time includes planning in both paths. Peak RSS covers all simulated roles, not evaluator memory alone. A range across two setups is an observed range, not a confidence interval.','']
    if all(k in data for k in ['threshold-count','native-count-d3']):
        a=data['threshold-count'][0];b=data['native-count-d3'][0]
        report_gain=100*(1-b['report_bytes']/a['report_bytes'])
        key_gain=100*(1-(b['rotation_key_bytes']+b['eval_mult_key_bytes'])/(a['rotation_key_bytes']+a['eval_mult_key_bytes']))
        lines += [f'Matched Count exact size change: ciphertext **{report_gain:.2f}% smaller**, total evaluation keys **{key_gain:.2f}% smaller**. '
                  'This keeps the field, predicate, packing geometry and nominal encryption target fixed; setup and decryption APIs differ. '
                  'It does not prove equal protocol security, minimum safe parameters, or deployment speedup.','']
    lines += ['Randomized native profiles declare Q=1,000,000 invalid attempts and a 128-bit global ideal bound; repetition counts were checked using exact integers. '
              'The lifetime attempt budget is an external assumption, not enforced by this study. Historical seven-repetition results do not have matched guarantees.','',
              'The smaller-prime CSV records context selection/rejection only. Wire coding headroom is an estimate, not achieved compression; FPC1 is unchanged. '
              'See NATIVE.md for changes, qualification coverage and security limitations.','']
    return '\n'.join(lines)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('directory',type=Path);args=parser.parse_args()
    report=summarize(args.directory);(args.directory/'summary.md').write_text(report);print(report)
