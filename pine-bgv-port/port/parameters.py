"""Exact-arithmetic admission preflight for pinned PINE reference parameters.
These are necessary reference guards, not a BGV/security certificate.
"""
from fractions import Fraction
import json

def profile(p, bound, dimension, ring, checks=100, alpha=Fraction(87,10)):
    if min(p,bound,dimension,ring,checks)<=0 or alpha<=0:
        raise ValueError('positive parameters required')
    a=alpha*bound
    ceiling=(a.numerator+a.denominator-1)//a.denominator
    wr=1 << ceiling.bit_length() # next power of two >= ceil(alpha*bound)+1
    failures=[]
    if p<=3*bound*bound+2: failures.append('norm range: p > 3*bound^2+2 required')
    if p<2*checks: failures.append('p >= 2*checks required')
    if p<2600*wr: failures.append('p >= 2600*wrap_bound required')
    if wr*wr>4000*p: failures.append('wrap_bound^2 <= 4000*p required')
    bits=2*(bound*bound).bit_length()+((2*wr-1).bit_length()+1)*checks
    transmitted=dimension+bits
    if transmitted>ring: failures.append('encoded input alone exceeds one polynomial; chunking required')
    return dict(p=p,bound=bound,dimension=dimension,ring=ring,wrap_bound=wr,
                encoded_input_elements=transmitted,query_input_elements=transmitted+checks,
                failures=failures,qualified_for_production=False,
                remaining=['proof capacity','NTT domains','BGV security and noise','challenge binding','privacy'])

if __name__=='__main__':
    print(json.dumps([profile(p,b,d,n) for p in (65537,786433,4293918721)
                     for b in (1,16,128) for d in (650,10000)
                     for n in (4096,8192,16384,32768)],indent=2))
