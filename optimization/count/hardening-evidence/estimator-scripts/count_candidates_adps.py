import json,math,time,struct
from sage.all import ZZ,oo,log
from estimator import LWE,ND,RC
rows=json.load(open('count_hardening_profiles.json'))[2:]
for row in rows:
 q=math.prod(map(int,row['qp_moduli']));assert math.gcd(row['p'],q)==1
 sigma=struct.unpack('f',struct.pack('f',3.19))[0]
 params=LWE.Parameters(n=row['n'],q=ZZ(q),Xs=ND.Uniform(-1,1),Xe=ND.DiscreteGaussian(sigma),m=oo,tag=row['name'])
 for label,model in [('ADPS16',RC.ADPS16)]:
  t=time.monotonic();print('START',row['name'],label,flush=True)
  result={}
  for name,fn in [('usvp',LWE.primal_usvp),('dual_hybrid',LWE.dual_hybrid)]:
   cost=fn(params,red_cost_model=model)
   result[name]={'log2_rop':float(log(cost['rop'],2)),'cost':str(cost)}
  print('RESULT_JSON '+json.dumps({'profile':row['name'],'n':row['n'],'QP_bits':q.bit_length(),'sigma':sigma,'m':'infinity','model':label,'results':result,'seconds':time.monotonic()-t}),flush=True)
