#!/usr/bin/env python3
"""Isolated, fail-closed full-circuit parameter ablation (Linux/OpenFHE 1.3.1).
No production source is mutated. Outputs contain no secret keys.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import statistics
import subprocess
import time


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def write(path, data):
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(json.dumps(data, indent=2) + '\n')
    tmp.replace(path)


def command(argv, cwd, env, log, timeout):
    start = time.monotonic()
    with log.open('x') as output:
        child = subprocess.Popen(argv, cwd=cwd, env=env, stdout=output,
                                 stderr=subprocess.STDOUT, start_new_session=True)
        try:
            rc = child.wait(timeout=timeout)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
            raise
    return {'argv': argv, 'returncode': rc, 'wall_s': time.monotonic() - start,
            'log': log.name, 'log_sha256': digest(log)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--processes', type=int, default=2,
                        help='fresh key setups per profile; batches within a setup are dependent')
    parser.add_argument('--batches', type=int, default=6)
    parser.add_argument('--timeout', type=int, default=2400, help='seconds per command')
    parser.add_argument('--full-suite', action='store_true',
                        help='also qualify Histogram exact, Sum randomized, SumVec exact')
    args = parser.parse_args()
    if args.processes < 2 or args.batches < 6 or args.timeout <= 0:
        parser.error('at least two independent setups and six batches are required')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[2]
    env = os.environ.copy()
    env.setdefault('OMP_NUM_THREADS', '2')
    if not env.get('OPENFHE_DIR'):
        parser.error('source your pinned OpenFHE/Rust environment first')
    manifest = {'status': 'running', 'scope': 'Count exact mode ablation',
                'encryption_target': 'OpenFHE HEStd_128_classic (not independently estimated)',
                'field': 786433, 'check': 'exact', 'reports_per_batch': 4,
                'processes_per_profile': args.processes, 'batches_per_process': args.batches,
                'warmup_batches': 0, 'omp_num_threads': env['OMP_NUM_THREADS'],
                'security_limit': 'same encryption setting and exact predicate; changing multiparty mode is NOT a proof of equivalent protocol security',
                'profiles': {}, 'runs': []}
    write(out / 'manifest.json', manifest)
    profiles = ('flooding', 'default-multiparty', 'default-with-headroom')
    try:
        for name in profiles:
            dest = out / name
            dest.mkdir()
            tree = dest / 'source'
            for crate in ('fhe-paper-core', 'fhe-prio3', 'openfhe-tbgv-rs'):
                shutil.copytree(root / crate, tree / crate,
                                ignore=shutil.ignore_patterns('target', 'results', '.git', '__pycache__'))
            shim = tree / 'openfhe-tbgv-rs/wrapper/tbgv.cpp'
            original = shim.read_text()
            needle = '    params.SetMultipartyMode(NOISE_FLOODING_MULTIPARTY);'
            if original.count(needle) != 1:
                raise RuntimeError('expected exactly one flooding mode assignment')
            if name != 'flooding':
                shim.write_text(original.replace(needle,
                    '    // Study only: OpenFHE 1.3.1 default FIXED_NOISE_MULTIPARTY.'))
            if name == 'default-with-headroom':
                depth_line = '    params.SetMultiplicativeDepth(mult_depth);'
                text = shim.read_text()
                if text.count(depth_line) != 1:
                    raise RuntimeError('expected exactly one depth assignment')
                shim.write_text(text.replace(depth_line, '    params.SetMultiplicativeDepth(mult_depth + 1);'))
            inventory = {str(p.relative_to(tree)): digest(p)
                         for p in sorted(tree.rglob('*')) if p.is_file()}
            write(dest / 'source-sha256.json', inventory)
            profile = {'source_inventory_sha256': digest(dest / 'source-sha256.json'),
                       'context_change': ('none' if name == 'flooding' else 'omit SetMultipartyMode; retain one-party threshold key setup') + ('; add one context level for unchanged threshold rebuild guard' if name == 'default-with-headroom' else ''),
                       'commands': [], 'qualified': False}
            manifest['profiles'][name] = profile
            penv = env | {'CARGO_TARGET_DIR': str(dest / 'target')}
            crate = tree / 'fhe-paper-core'
            commands = [(['cargo', 'build', '--release', '--locked', '--bin', 'paper_core_eval'], 'build.log'),
                        (['cargo', 'test', '--release', '--locked', '--test', 'study_count', '--', '--nocapture', '--test-threads=1'], 'qualification-count.log')]
            if args.full_suite:
                commands.append((['cargo', 'test', '--release', '--locked', '--test', 'paper_core', '--', '--nocapture', '--test-threads=1'], 'qualification-other-tasks.log'))
            for argv, log in commands:
                print(name, log, flush=True)
                result = command(argv, crate, penv, dest / log, args.timeout)
                profile['commands'].append(result)
                write(out / 'manifest.json', manifest)
                if result['returncode']:
                    profile['rejected_at'] = log
                    break
            if profile.get('rejected_at'):
                write(out / 'manifest.json', manifest)
                continue
            binary = dest / 'target/release/paper_core_eval'
            profile['binary_sha256'] = digest(binary)
            # Record linked shared libraries, including exact binary hashes.
            linked = subprocess.check_output(['ldd', str(binary)], text=True)
            (dest / 'ldd.txt').write_text(linked)
            profile['openfhe_library_sha256'] = {
                line.split('=>', 1)[1].strip().split()[0]:
                digest(Path(line.split('=>', 1)[1].strip().split()[0]))
                for line in linked.splitlines() if 'libOPENFHE' in line and '=>' in line}
            profile['qualified'] = True
            write(out / 'manifest.json', manifest)
        if not any(p['qualified'] for p in manifest['profiles'].values()):
            raise RuntimeError('no profile qualified; no performance comparison is possible')
        # Reverse order on alternating rounds to reduce simple ordering bias.
        for repeat in range(args.processes):
            names = [name for name in profiles if manifest['profiles'][name]['qualified']]
            if repeat % 2:
                names.reverse()
            for name in names:
                dest = out / name
                binary = dest / 'target/release/paper_core_eval'
                if digest(binary) != manifest['profiles'][name]['binary_sha256']:
                    raise RuntimeError('binary changed after qualification')
                sample = dest / f'count-exact-{repeat}.json'
                print(name, sample.name, flush=True)
                result = command([str(binary), 'exact', '--type', 'count', '--reports', '4',
                                  '--batches', str(args.batches), '--seed', str(100 + repeat),
                                  '--out', str(sample)], dest / 'source/fhe-paper-core',
                                 env, dest / f'count-exact-{repeat}.log', args.timeout)
                result.update(profile=name, repeat=repeat)
                manifest['runs'].append(result)
                if result['returncode']:
                    raise RuntimeError(f'{name} benchmark failed; no success summary')
                d = json.loads(sample.read_text())
                if (d['check'], d['type'], d['reports_per_batch'], d['batches']) != ('exact', 'count', 4, args.batches):
                    raise RuntimeError('measurement configuration mismatch')
                if len(d['evaluator_total_per_batch_ms']) != args.batches or d['peak_rss_kb'] <= 0:
                    raise RuntimeError('incomplete timing or missing memory measurement')
                result['sample_sha256'] = digest(sample)
                write(out / 'manifest.json', manifest)
        summary = {}
        for name in profiles:
            if not manifest['profiles'][name]['qualified']:
                summary[name] = {'status': 'rejected; no benchmark'}
                continue
            samples = [json.loads(p.read_text()) for p in sorted((out / name).glob('count-exact-*.json'))]
            metrics = ['report_bytes', 'serialized_report_bytes', 'rotation_key_bytes',
                       'eval_mult_key_bytes', 'public_key_bytes', 'setup_ms', 'peak_rss_kb',
                       'wall_s', 'ring_dim', 'log2_q', 'towers']
            summary[name] = {key: [d[key] for d in samples] for key in metrics}
            summary[name]['per_setup_evaluator_median_ms_per_report'] = [
                statistics.median(d['evaluator_total_per_batch_ms']) / 4 for d in samples]
        write(out / 'summary.json', summary)
        manifest['status'] = ('completed_with_rejections' if any(not p['qualified'] for p in manifest['profiles'].values()) else 'completed')
    except BaseException as exc:
        manifest['status'] = 'failed'
        manifest['error'] = f'{type(exc).__name__}: {exc}'
        raise
    finally:
        write(out / 'manifest.json', manifest)


if __name__ == '__main__':
    main()
