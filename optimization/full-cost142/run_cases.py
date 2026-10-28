"""Sequential runs; keep failed logs. No keys/parameters changed on failures."""
import json,os,pathlib,subprocess,sys
root=pathlib.Path(__file__).resolve().parent
out=pathlib.Path(sys.argv[1]);scope=sys.argv[2];out.mkdir(parents=True,exist_ok=True)
target=pathlib.Path(os.environ['CARGO_TARGET_DIR'])/'release'
boolean=pathlib.Path('/workspace/fhe-validation/full-cost142/boolean-cost')
if scope=='preflight': cases=[('prio','count',1),('boolean','count',1),('bgv','count',1),('bgv','sumvec',10)]
elif scope=='length100': cases=[('prio','sumvec',100),('boolean','sumvec',100),('bgv','sumvec',100)]
elif scope=='vectors': cases=[(b,'sumvec',l) for l in [10,25,50,100] for b in ['prio','boolean','bgv']]
elif scope=='all':
    cases=[(b,t,l) for t,l in [('count',1),('sum',1),('histogram',3),('histogram',8),('sumvec',10),('sumvec',25),('sumvec',50),('sumvec',100)] for b in ['prio','boolean','bgv'] if b!='boolean' or t in ['count','sumvec']]
else: raise ValueError('scope')
for backend,task,length in cases:
    name=f'{backend}-{task}-{length}'
    executable=boolean if backend=='boolean' else target/(backend+'_cost')
    command=[str(executable),str(length)] if backend=='boolean' else [str(executable),task,str(length)]
    command=['taskset','-c','0']+command
    print('START',name,flush=True)
    result=subprocess.run([sys.executable,str(root/'measure.py'),str(out/(name+'.jsonl')),str(out/(name+'.stderr'))]+command)
    with (out/'exits.jsonl').open('a') as log:log.write(json.dumps({'case':name,'exit':result.returncode})+'\n')
    print('EXIT',name,result.returncode,flush=True)
    if result.returncode:sys.exit(result.returncode)
