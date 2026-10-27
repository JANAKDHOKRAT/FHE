import json,math,time
from sage.all import ZZ,oo,log
from estimator import LWE,ND
rows=json.load(open('count_profiles.json'))
for row in rows:
 q=math.prod(row['qp_moduli']);assert math.gcd(row['p'],q)==1
 params=LWE.Parameters(n=row['n'],q=ZZ(q),Xs=ND.Uniform(-1,1),Xe=ND.DiscreteGaussian(row['sigma']),m=oo,tag=row['name'])
 print('START',row['name'],'QPbits',q.bit_length(),flush=True);t=time.monotonic()
 results=LWE.estimate.rough(params,jobs=1,catch_exceptions=False)
 output={name:{'log2_rop':float(log(cost['rop'],2)),'cost':str(cost)} for name,cost in results.items()}
 print('RESULT_JSON '+json.dumps({'profile':row['name'],'n':row['n'],'modulus':'full QP','sigma':row['sigma'],'model':'ADPS16, rough primal_usvp and dual_hybrid','results':output,'seconds':time.monotonic()-t}),flush=True)
