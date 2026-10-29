"""Verify actual fork context against independent rational bounds; not security proof."""
import json,pathlib,math
from fractions import Fraction as F
import bounds
root=pathlib.Path(__file__).resolve().parent
r=json.loads((root/'context100-fast.jsonl').read_text());assert r['status']=='CUSTOM_CONTEXT_PARAMETERS_ONLY'
assert (r['p'],r['ring'],r['depth'],r['digit'],r['switches'],r['adds'])==(65537,32768,23,8,7,1)
assert r['alpha']==36 and r['threshold_parties']==1 and F(r['sigma'])<=bounds.sigma
q=r['q'];assert len(q)==25 and len(set(q))==25
assert all(v<2**60 and v!=65537 and (v-1)%65536==0 and bounds.prime(v) for v in q)
f,m,e=bounds.upper(8,7)
assert q[0]>=f and q[-1]>=e and all(v>=m for v in q[1:-1])
assert math.prod(q).bit_length()==r['actual_Q_bits']<=881
out={'status':'ACTUAL_CONTEXT_BOUND_CHECK_PASS','actual_Q_bits':r['actual_Q_bits'],'all_primes_verified':True,'all_stated_noise_bounds_preserved':True,'full_encryption_security_proven':False,'complete_noise_failure_theorem_proven':False,'encrypted_circuit_tested':False}
(root/'context-bound-check-fast.json').write_text(json.dumps(out,indent=2)+'\n');print(out)
