#!/usr/bin/env python3
"""Matched real-process runs. Run after sourcing paper-env.sh and building both binaries.
Retains failures; correctness is asserted inside each executable. No invented data.
"""
import datetime, json, os, pathlib, platform, resource, subprocess, time, sys, signal
ROOT=pathlib.Path(__file__).resolve().parent
BIN=pathlib.Path(os.environ['CARGO_TARGET_DIR'])/'release'
CASES=[['count'],['bitvec','--len','10'],['bitvec','--len','100'],['sum','--max','100'],['sumvec','--len','10','--max','3'],['sumvec','--len','100','--max','1'],['histogram','--len','100'],['multihot','--len','100','--weight','10']]
# Protect the host from the large, non-streaming implementation. A resource
# refusal is a failed measurement, not an extrapolated successful run.
def limits():
    resource.setrlimit(resource.RLIMIT_AS,(28*1024**3,28*1024**3))
def main():
    sizes=[int(x) for x in os.environ.get('BATCHES','16,256,1024').split(',')]
    machine={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'platform':platform.platform(),'omp_threads':os.environ.get('OMP_NUM_THREADS'),'openfhe':os.environ.get('OPENFHE_DIR'),'target':str(BIN),'batch_sizes':sizes,'address_space_limit_gib':28,'timeout_seconds':1800,'repetitions':1,'gate':'honest-input phase range guard implemented; no noise-hiding or production security certification','source_manifest':'source-hashes.json'}
    for label,cmd in [('cpu',['lscpu']),('rust',['rustc','--version']),('git',['git','rev-parse','HEAD'])]:
        machine[label]=subprocess.run(cmd,capture_output=True,text=True).stdout
    (ROOT/'machine.json').write_text(json.dumps(machine,indent=2))
    with (ROOT/'measurements.jsonl').open('a',buffering=1) as out:
        for n in sizes:
            for field in ['65537','prio2']:
                for case in CASES:
                    for name in ['measure_single','measure_oblivious']:
                        cmd=[str(BIN/name),*case,'--field',field,'--reports',str(n)]
                        record={'command':cmd,'reports':n,'field':field,'case':case,'mode':name}
                        start=time.monotonic()
                        proc=subprocess.Popen([sys.executable,str(ROOT/'resource_run.py'),*cmd],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,preexec_fn=limits,start_new_session=True)
                        try:
                            stdout,stderr=proc.communicate(timeout=1800)
                            record.update(exit_code=proc.returncode,stdout=stdout,stderr=stderr)
                            if proc.returncode==0:
                                record['measurement']=json.loads(stdout.strip().splitlines()[-1])
                        except subprocess.TimeoutExpired:
                            # Terminate both the resource wrapper and its benchmark child.
                            os.killpg(proc.pid,signal.SIGKILL)
                            stdout,stderr=proc.communicate()
                            record.update(exit_code=proc.returncode,error='timeout',stdout=stdout,stderr=stderr)
                        record['wall_seconds']=time.monotonic()-start
                        out.write(json.dumps(record)+'\n')
                        print(n,field,case,name,record['exit_code'],round(record['wall_seconds'],2),flush=True)
if __name__=='__main__': main()
