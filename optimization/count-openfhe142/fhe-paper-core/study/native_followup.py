#!/usr/bin/env python3
"""Qualify bounded Count packing and deeper exact circuits at ring <=65536."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
import json
import os
from pathlib import Path
import subprocess
import tarfile
from run import command,digest,write


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--selection',type=Path,required=True)
    args=ap.parse_args()
    root=Path(__file__).resolve().parents[2];crate=root/'fhe-paper-core'
    out=args.out.resolve();out.mkdir(parents=True,exist_ok=False)
    env=os.environ.copy();env.setdefault('OMP_NUM_THREADS','2')
    rows=list(csv.DictReader(args.selection.open()))
    def smallest(task):
        eligible=[int(r['digits']) for r in rows if r['prime']=='786433' and r['task']==task and r['mode']=='exact' and r['status']=='selected' and r['ring']=='65536']
        return min(eligible) if eligible else None
    count=smallest('count')
    if count is None:raise RuntimeError('no selected Count profile')
    profiles=[('count-full', 'count',count,None,4),('count-g2','count',count,2,4),
              ('count-g4','count',count,4,4),('count-g32-n32','count',count,32,32)]
    for length in [25,50,100]:
        digits=smallest(f'sv{length}')
        if digits is not None:profiles.append((f'sv{length}-exact',f'sumvec:{length}:1',digits,None,4))
    m={'status':'building','scope':'bounded opt-in native candidates; not production-security certification',
       'nominal_encryption_security_bits':128,'ring_cap':65536,'native_depth_cap':32,
       'operational_batch_limit':32,'batches_per_key':3,'keys_per_profile':1,
       'qualification':'valid/invalid, parser and cross-slot cases; fill to 32 admissions and refuse 33rd',
       'selection_sha256':digest(args.selection),'profiles':{},'runs':[]}
    write(out/'manifest.json',m)
    try:
        build=command(['cargo','test','--release','--locked','--test','native_tasks','--no-run','--message-format=json'],crate,env,out/'build.log',2400)
        if build['returncode']:raise RuntimeError('qualification build failed')
        executable=None
        for line in (out/'build.log').read_text().splitlines():
            try:d=json.loads(line)
            except json.JSONDecodeError:continue
            if d.get('reason')=='compiler-artifact' and d.get('target',{}).get('name')=='native_tasks' and d.get('executable'):executable=Path(d['executable'])
        if executable is None:raise RuntimeError('no native qualification binary')
        binary=Path(env['CARGO_TARGET_DIR'])/'release/paper_core_eval'
        result=command(['cargo','build','--release','--locked','--bin','paper_core_eval'],crate,env,out/'build-benchmark.log',2400)
        if result['returncode']:raise RuntimeError('benchmark build failed')
        m.update(binary_sha256=digest(binary),qualification_binary_sha256=digest(executable))
        source={}
        with tarfile.open(out/'source.tar.gz','w:gz') as archive:
            for package in ['fhe-paper-core','fhe-prio3','openfhe-tbgv-rs']:
                for p in sorted((root/package).rglob('*')):
                    if not p.is_file() or any(x in p.relative_to(root/package).parts for x in ['target','results','__pycache__']):continue
                    source[str(p.relative_to(root))]=digest(p);archive.add(p,arcname=str(p.relative_to(root)))
        write(out/'source-sha256.json',source)
        def qualify(spec):
            name,ty,digits,groups,reports=spec
            directory=out/name;directory.mkdir()
            penv=env|{'NATIVE_TEST_PRIME':'786433','NATIVE_TEST_TYPE':ty.split(':')[0],
                      'NATIVE_TEST_MODE':'exact','NATIVE_TEST_DIGITS':str(digits),'NATIVE_TEST_LIMIT':'32'}
            if ty.startswith('sumvec:'):penv['NATIVE_TEST_LENGTH']=ty.split(':')[1]
            if groups:penv['NATIVE_TEST_GROUPS']=str(groups)
            print('qualifying',name,flush=True)
            result=command([str(executable),'--nocapture','--test-threads=1'],crate,penv,directory/'qualification.log',3600)
            return name,{'type':ty,'digits':digits,'groups':groups,'reports':reports,'qualified':result['returncode']==0,'qualification':result}
        m['status']='qualifying';write(out/'manifest.json',m)
        with ThreadPoolExecutor(max_workers=2) as pool:
            for future in as_completed([pool.submit(qualify,p) for p in profiles]):
                name,profile=future.result();m['profiles'][name]=profile;write(out/'manifest.json',m)
                print('QUALIFIED' if profile['qualified'] else 'REJECTED',name,flush=True)
        m['status']='measuring';write(out/'manifest.json',m)
        for name,_,_,_,_ in profiles:
            p=m['profiles'][name]
            if not p['qualified']:continue
            if digest(binary)!=m['binary_sha256']:raise RuntimeError('binary changed')
            directory=out/name;path=directory/'measurement.json'
            argv=[str(binary),'exact','--type',p['type'],'--key-mode','single','--digits',str(p['digits']),
                  '--batch-limit','32','--reports',str(p['reports']),'--batches','3','--seed','2026','--out',str(path)]
            if p['groups']:argv+=['--groups',str(p['groups'])]
            print('measuring',name,flush=True)
            result=command(argv,crate,env,directory/'measurement.log',3600)
            result['profile']=name;m['runs'].append(result)
            if result['returncode']:raise RuntimeError(f'{name}: timing failed')
            d=json.loads(path.read_text())
            if (d['type'],d['check'],d['reports_per_batch'],d['batches'],d['max_batch'])!=(p['type'],'exact',p['reports'],3,32):raise RuntimeError('configuration mismatch')
            if d['ring_dim']>65536 or d['security_bits']!=128:raise RuntimeError('resource/security contract violated')
            result['measurement_sha256']=digest(path);write(out/'manifest.json',m)
        m['status']='completed_with_rejections' if any(not p['qualified'] for p in m['profiles'].values()) else 'completed'
    except BaseException as e:m['status']='failed';m['error']=str(e);raise
    finally:write(out/'manifest.json',m)


if __name__=='__main__':main()
