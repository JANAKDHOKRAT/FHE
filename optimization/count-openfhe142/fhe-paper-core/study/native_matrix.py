#!/usr/bin/env python3
"""Complete encrypted native profile study. No parameter mutations or fake costs."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess
import tarfile
import time
from run import command, digest, write


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--batches',type=int,default=3,
                        help='screening batches per fresh key; Count controls always use at least six and two keys')
    args=parser.parse_args()
    if args.batches<3:parser.error('at least three screening batches')
    root=Path(__file__).resolve().parents[2]
    crate=root/'fhe-paper-core'
    env=os.environ.copy();env.setdefault('OMP_NUM_THREADS','2')
    if not env.get('OPENFHE_DIR'):parser.error('activate pinned OpenFHE/Rust environment')
    out=args.out.resolve();out.mkdir(parents=True,exist_ok=False)
    manifest={'status':'building','nominal_encryption_security_bits':128,
              'randomized_contract':{'global_target_bits':128,'invalid_attempt_budget':1000000,
                                      'budget_enforcement':'assumed externally, not implemented across key lifetime'},
              'screening_batches':args.batches,'warmup_batches':0,'qualification_parallelism':2,
              'timing_parallelism':1,'profiles':{},'runs':[],
              'limitations':['finite tests are not a malicious-ciphertext security proof',
                             'within-key timing samples are correlated; no statistical CI claimed',
                             'global OpenFHE initialization and keys are serialized within each process',
                             'N=4 and N=32 are experimental workloads, not deployment throughput']}
    write(out/'manifest.json',manifest)
    try:
        artifacts={}
        for test in ['native_tasks','study_count']:
            log=out/f'build-{test}.log'
            result=command(['cargo','test','--release','--locked','--test',test,'--no-run','--message-format=json'],
                           crate,env,log,2400)
            if result['returncode']:raise RuntimeError(f'{test} build failed')
            for line in log.read_text().splitlines():
                try:d=json.loads(line)
                except json.JSONDecodeError:continue
                if d.get('reason')=='compiler-artifact' and d.get('target',{}).get('name')==test and d.get('executable'):
                    artifacts[test]=Path(d['executable'])
            if test not in artifacts:raise RuntimeError('missing compiled test executable')
        result=command(['cargo','build','--release','--locked','--bin','paper_core_eval'],crate,env,out/'build-benchmark.log',2400)
        if result['returncode']:raise RuntimeError('benchmark build failed')
        binary=Path(env['CARGO_TARGET_DIR'])/'release/paper_core_eval'
        manifest['binary_sha256']=digest(binary)
        manifest['qualification_binary_sha256']={k:digest(v) for k,v in artifacts.items()}
        linked=subprocess.check_output(['ldd',str(binary)],text=True)
        (out/'ldd.txt').write_text(linked)
        manifest['linked_openfhe_sha256']={line.split('=>')[1].strip().split()[0]:digest(Path(line.split('=>')[1].strip().split()[0]))
                                            for line in linked.splitlines() if 'libOPENFHE' in line and '=>' in line}
        source={}
        with tarfile.open(out/'source.tar.gz','w:gz') as archive:
            for package in ['fhe-paper-core','fhe-prio3','openfhe-tbgv-rs']:
                for p in sorted((root/package).rglob('*')):
                    if not p.is_file() or any(v in p.relative_to(root/package).parts for v in ['target','results','__pycache__']):continue
                    source[str(p.relative_to(root))]=digest(p)
                    archive.add(p,arcname=str(p.relative_to(root)))
        write(out/'source-sha256.json',source)
        (out/'source.patch').write_bytes(subprocess.check_output(['git','diff','HEAD','--','prio3/fhe-paper-core','prio3/fhe-prio3','prio3/openfhe-tbgv-rs'],cwd=root.parent))
        # Each profile must pass a complete encrypted test before any timings.
        profiles=[('threshold-count','count','exact',None,None,4),
                  ('native-count-d3','count','exact',3,None,4),
                  ('native-count-d5','count','exact',5,None,4),
                  ('native-sum-exact','sum:100','exact',3,None,4),
                  ('native-hist-exact','histogram:8','exact',3,None,4),
                  ('native-sv10-exact','sumvec:10:1','exact',3,None,4),
                  ('native-count-random','count','randomised',3,None,4),
                  ('native-sum-random','sum:100','randomised',3,None,4),
                  ('native-hist-random','histogram:8','randomised',3,None,4),
                  ('native-sv100-random','sumvec:100:1','randomised',3,None,4),
                  ('native-sv100-g16','sumvec:100:1','randomised',3,16,4),
                  ('native-sv100-n32','sumvec:100:1','randomised',3,None,32)]
        def qualify(profile):
            name,ty,mode,digits,groups,reports=profile
            directory=out/name;directory.mkdir()
            penv=env.copy()
            test='study_count' if digits is None else 'native_tasks'
            if digits is not None:
                parts=ty.split(':')
                penv.update(NATIVE_TEST_PRIME='786433',NATIVE_TEST_DIGITS=str(digits),NATIVE_TEST_MODE=mode,NATIVE_TEST_TYPE=parts[0])
                if len(parts)>1 and parts[0] in ['sumvec','histogram']:penv['NATIVE_TEST_LENGTH']=parts[1]
                if groups:penv['NATIVE_TEST_GROUPS']=str(groups)
            print('qualifying',name,flush=True)
            result=command([str(artifacts[test]),'--nocapture','--test-threads=1'],crate,penv,directory/'qualification.log',2400)
            return name,{'type':ty,'mode':mode,'digits':digits,'groups':groups,'reports':reports,
                        'qualification':result,'qualified':result['returncode']==0}
        manifest['status']='qualifying';write(out/'manifest.json',manifest)
        with ThreadPoolExecutor(max_workers=2) as pool:
            for future in as_completed([pool.submit(qualify,p) for p in profiles]):
                name,result=future.result();manifest['profiles'][name]=result
                write(out/'manifest.json',manifest)
                print('qualified' if result['qualified'] else 'REJECTED',name,flush=True)
        if not manifest['profiles']['threshold-count']['qualified']:
            raise RuntimeError('retained threshold regression failed; stop')
        manifest['status']='measuring';write(out/'manifest.json',manifest)
        # No qualification, compilation, or other study workloads overlap timing.
        # Matched Count comparison gets two independent keys; other rows screen
        # one key each, and cannot support precise population performance claims.
        rounds=[(name,0) for name,_,_,_,_,_ in profiles if manifest['profiles'][name]['qualified']]
        rounds += [(name,1) for name in ['native-count-d3','threshold-count'] if manifest['profiles'][name]['qualified']]
        for name,repeat in rounds:
            if digest(binary)!=manifest['binary_sha256']:raise RuntimeError('measurement binary changed')
            p=manifest['profiles'][name];directory=out/name
            batches=max(6,args.batches) if name in ['threshold-count','native-count-d3'] else args.batches
            path=directory/f'measurement-{repeat}.json'
            argv=[str(binary),p['mode'],'--type',p['type'],'--reports',str(p['reports']),
                  '--batches',str(batches),'--seed',str(100+repeat),'--out',str(path)]
            if p['digits'] is not None:
                argv+=['--key-mode','single','--plain-mod','786433','--attempts','1000000',
                       '--soundness-bits','128','--digits',str(p['digits'])]
                if p['groups']:argv+=['--groups',str(p['groups'])]
            print('measuring',name,repeat,flush=True)
            result=command(argv,crate,env,directory/f'measurement-{repeat}.log',3600)
            result.update(profile=name,repeat=repeat)
            manifest['runs'].append(result)
            if result['returncode']:
                write(out/'manifest.json',manifest)
                raise RuntimeError(f'{name}: benchmark failed; retained as failure, no success summary')
            d=json.loads(path.read_text())
            if (d['type'],d['check'],d['reports_per_batch'],d['batches'])!=(p['type'],p['mode'],p['reports'],batches):raise RuntimeError('configuration mismatch')
            if len(d['evaluator_total_per_batch_ms'])!=batches:raise RuntimeError('missing batches')
            result['measurement_sha256']=digest(path)
            write(out/'manifest.json',manifest)
        manifest['status']='completed_with_rejections' if any(not p['qualified'] for p in manifest['profiles'].values()) else 'completed'
    except BaseException as exc:
        manifest['status']='failed';manifest['error']=str(exc);raise
    finally:write(out/'manifest.json',manifest)


if __name__=='__main__':main()
