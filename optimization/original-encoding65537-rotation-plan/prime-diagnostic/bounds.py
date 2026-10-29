"""Exact rational enclosure of upstream BV/FLEXIBLEAUTOEXT noise formulas.
Parameter-only research: does NOT construct or certify an FHE context.
"""
from fractions import Fraction as F
from math import isqrt,prod
import json,struct,pathlib
n=32768;p=65537;depth=23;num_primes=24
scale=1<<128;lo=F(isqrt(n*scale*scale),scale);hi=lo+F(1,scale)
sigma=F(struct.unpack('f',struct.pack('f',3.19))[0]);B=sigma*6
Vlo=1+4*lo;Vhi=1+4*hi;delta=2*hi;fresh=B*(1+2*delta)
def upper(digit,switches):
 K=(60//digit+1)*num_primes*delta*(1<<digit)*B/2
 first=2*p*fresh-p
 extra=2*(fresh*2+switches*K)/Vlo
 main=(2*Vhi+2+hi/(2*Vlo))*delta*p*2+2*(switches+1)*K/Vlo
 return first,main,extra
# Deterministic Miller-Rabin for unsigned 64-bit integers.
def prime(x):
 if x<2:return False
 for a in (2,3,5,7,11,13,17,19,23,29,31,37):
  if x%a==0:return x==a
 d=x-1;s=0
 while d%2==0:d//=2;s+=1
 for a in (2,325,9375,28178,450775,9780504,1795265022):
  if a%x==0:continue
  v=pow(a,d,x)
  if v in (1,x-1):continue
  for _ in range(s-1):
   v=v*v%x
   if v==x-1:break
  else:return False
 return True
def nextq(bound,used):
 b=(bound.numerator+bound.denominator-1)//bound.denominator
 q=((b-1+65535)//65536)*65536+1
 while q==p or q in used or not prime(q):q+=65536
 assert q>=bound and (q-1)%65536==0 and prime(q)
 return q
rows=[]
for digit,ks in ((8,7),(8,9),(10,2),(12,1)):
 first,main,extra=upper(digit,ks);q=[]
 q.append(nextq(first,set(q)))
 for _ in range(depth):q.append(nextq(main,set(q)))
 q.append(nextq(extra,set(q)))
 Q=prod(q);bits=Q.bit_length()
 rows.append({'digit':digit,'switches':ks,'depth':23,'adds':1,'ring':n,'p':p,'sigma_exact':str(sigma),'alpha':36,'q':q,'actual_Q_bits':bits,'within_881_bit_table_bound':bits<=881,'all_moduli_above_rational_upstream_bounds':True,'bound_fractions':{'first':str(first),'main':str(main),'extension':str(extra)},'context_constructed':False,'encrypted_circuit_tested':False,'security_proven':False})
path=pathlib.Path(__file__).with_name('bounds.json');path.write_text(json.dumps(rows,indent=2)+'\n')
for r in rows:print({k:v for k,v in r.items() if k not in ('q','bound_fractions')})
