#!/usr/bin/env python3
"""Bounded Count experiment. Expected security gaps are findings, never passes."""
import hashlib,json,os,pathlib,subprocess,time,tarfile
from concurrent.futures import ThreadPoolExecutor,as_completed
R=pathlib.Path(__file__).resolve().parent
E=R/'evidence'
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,d):p.write_text(json.dumps(d,indent=2)+'\n')
def run(argv,log,env=None,timeout=1800):
 t=time.monotonic()
 with log.open('w') as f:
  try:rc=subprocess.run(argv,cwd=R/'fhe-paper-core',env=env,stdout=f,stderr=subprocess.STDOUT,timeout=timeout).returncode
  except subprocess.TimeoutExpired:rc=124
 return {'argv':argv,'returncode':rc,'seconds':time.monotonic()-t,'log':str(log.relative_to(R)),'sha256':digest(log)}
def main():
 E.mkdir(exist_ok=True)
 env=os.environ.copy()
 exe=None;algebra=None
 for line in (E/'build-tests.jsonl').read_text().splitlines():
  try:d=json.loads(line)
  except json.JSONDecodeError:continue
  if d.get('reason')=='compiler-artifact' and d.get('executable'):
   if d['target']['name']=='native_tasks':exe=d['executable']
   if d['target']['name']=='count_algebra':algebra=d['executable']
 assert exe and algebra
 binary=pathlib.Path(env['CARGO_TARGET_DIR'])/'release/paper_core_eval'
 profiles=[('baseline-g4',786433,2,False,4,4),('projected-large-g4',786433,2,True,4,4),('projected-small-g4',65537,7,True,4,4),('projected-small-full',65537,7,True,None,4),('projected-small-g32',65537,7,True,32,32)]
 m={'status':'running','production_security_gate':'NOT GREEN: arbitrary-ciphertext security, malicious-evaluator integrity, release/authentication and service DoS protection are not established','binary_sha256':digest(binary),'qualification_binary_sha256':digest(pathlib.Path(exe)),'profiles':{},'runs':[],'keys_per_profile':2,'batches_per_key':3,'operational_max_batch':32}
 save(E/'manifest.json',m)
 source={}
 with tarfile.open(E/'source.tar.gz','w:gz') as tar:
  for package in ['fhe-paper-core','fhe-prio3','openfhe-tbgv-rs']:
   for p in sorted((R/package).rglob('*')):
    if p.is_file() and not any(x in p.parts for x in ['target','__pycache__']):source[str(p.relative_to(R))]=digest(p);tar.add(p,arcname=str(p.relative_to(R)))
 save(E/'source-sha256.json',source)
 m['algebra']=run([algebra,'--nocapture'],E/'algebra.log',env)
 assert m['algebra']['returncode']==0
 def qualify(spec):
  name,p,d,projection,g,n=spec;out=E/name;out.mkdir(exist_ok=False)
  penv=env|{'NATIVE_TEST_TYPE':'count','NATIVE_TEST_MODE':'exact','NATIVE_TEST_PRIME':str(p),'NATIVE_TEST_DIGITS':str(d),'NATIVE_TEST_LIMIT':'32','COUNT_PROJECTION':str(projection).lower()}
  if g:penv['NATIVE_TEST_GROUPS']=str(g)
  print('qualifying',name,flush=True)
  return name,run([exe,'--nocapture','--test-threads=1'],out/'qualification.log',penv)
 with ThreadPoolExecutor(max_workers=2) as pool:
  for fut in as_completed([pool.submit(qualify,p) for p in profiles]):
   name,res=fut.result();m['profiles'][name]=res;save(E/'manifest.json',m);print('QUALIFIED' if res['returncode']==0 else 'FAILED',name,flush=True)
 for name,p,d,projection,g,n in profiles:
  if m['profiles'][name]['returncode']!=0:continue
  for key in [1,2]:
   assert digest(binary)==m['binary_sha256']
   path=E/name/f'key-{key}.json'
   argv=[str(binary),'exact','--type','count','--key-mode','single','--plain-mod',str(p),'--digits',str(d),'--count-projection',str(projection).lower(),'--batch-limit','32','--reports',str(n),'--batches','3','--seed',str(2026+key),'--out',str(path)]
   if g:argv+=['--groups',str(g)]
   print('measuring',name,'key',key,flush=True)
   res=run(argv,E/name/f'key-{key}.log',env);res.update(profile=name,key=key)
   if res['returncode']==0:
    result=json.loads(path.read_text());assert result['count_projection']==projection and result['plain_mod']==p and result['reports_per_batch']==n and result['max_batch']==32
    assert result['security_bits']==128
    if p==65537:assert result['ring_dim']==32768
    res['measurement_sha256']=digest(path)
   m['runs'].append(res);save(E/'manifest.json',m)
 m['status']='completed' if all(p['returncode']==0 for p in m['profiles'].values()) and all(r['returncode']==0 for r in m['runs']) else 'completed_with_failures'
 save(E/'manifest.json',m)
if __name__=='__main__':main()
