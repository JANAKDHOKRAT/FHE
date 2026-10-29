"""Pinned lattice-estimator, run with Sage. Model estimates, not security proofs."""
import json,math,struct,time,sys
from pathlib import Path
from sage.all import ZZ,oo,log
from estimator import LWE,ND,RC

root=Path('/study')
sigma=struct.unpack('f',struct.pack('f',3.19))[0]
rows=json.loads((root/'evidence'/ (sys.argv[1] if len(sys.argv)>1 else 'screen-input.json')).read_text())
for row in rows:
 q=math.prod(map(int,row['qp']))
 assert math.gcd(65537,q)==1 and row['ring']==32768
 params=LWE.Parameters(n=32768,q=ZZ(q),Xs=ND.Uniform(-1,1),Xe=ND.DiscreteGaussian(sigma),m=oo,tag=row['name'])
 for name,model in [('ADPS16',RC.ADPS16),('MATZOV',RC.MATZOV)]:
  attacks=[('usvp',LWE.primal_usvp),('dual_hybrid',LWE.dual_hybrid),('bdd',LWE.primal_bdd),('dual',LWE.dual)]
  if len(sys.argv)>2 and sys.argv[2]=='primal-only': attacks=attacks[:1]
  for attack,fn in attacks:
   start=time.monotonic()
   print(json.dumps({'status':'START','profile':row['name'],'model':name,'attack':attack}),flush=True)
   try:
    cost=fn(params,red_cost_model=model)
    print(json.dumps({'status':'ESTIMATE','profile':row['name'],'model':name,'attack':attack,'log2_rop':float(log(cost['rop'],2)),'cost':str(cost),'seconds':time.monotonic()-start,'log2QP':math.log2(q),'sigma':sigma,'n':32768,'m':'infinity','security_proven':False}),flush=True)
   except Exception as e:
    print(json.dumps({'status':'FAILED','profile':row['name'],'model':name,'attack':attack,'reason':str(e)}),flush=True)
