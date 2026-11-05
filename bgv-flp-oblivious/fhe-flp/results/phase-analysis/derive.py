"""Exact integer honest-phase bounds for the inspected OpenFHE 1.3.1 path.
Not an IND-CPA-D/circuit-privacy proof. No observed noise enters the derivation.
"""
import json, math, pathlib
ROOT=pathlib.Path(__file__).resolve().parent

def ceildiv(a,b):return (a+b-1)//b

def derive(row,products):
    p,n,e=row['p'],row['ring'],row['error_support_bound']
    qs=row['moduli'];Q=math.prod(qs);w=row['flood_width']
    assert e==39 and all(q%p==1 for q in qs)
    # pk=(p*e_pk-a*s,a); encryption uses ternary u,s and bounded e0,e1.
    H=(p-1)+p*(2*n+1)*e
    # Up to products dense plaintext products, each ||q||inf <= p-1.
    A=products*n*(p-1)*H+(p-1)
    flood=p*(1<<(w-1))
    bound=A+flood
    modulus=Q
    assert bound*2<modulus
    history=[]
    for q in reversed(qs[1:]):
        # Each component adds p*delta before division by q. Centered delta
        # has magnitude <=floor(q/2). Secret has l1 <= n.
        bound=ceildiv(bound+p*(q//2)*(n+1),q)
        modulus//=q
        assert bound*2<modulus
        history.append(bound)
    shift=ceildiv(2*A,p)
    # These certify ONLY smoothing of phase coordinates under stated fixed-
    # plaintext shift assumptions. They do not account for exposed c1.
    single_bits=w-math.log2(shift)
    vector_bits=single_bits-math.log2(n)
    return dict(p=p,ring=n,products=products,fresh_phase_bound=H,pre_flood_bound=A,
        flood_width=w,post_reduce_bounds=history,honest_phase_bound=bound,
        observed_phase=row['observed_max_phase'],observed_below_bound=row['observed_max_phase']<=bound,
        phase_only_single_coefficient_bits=single_bits,phase_only_vector_bits=vector_bits,
        meets_64_vector_bound=(n*shift*(1<<64)<=(1<<w)),
        full_ciphertext_security_proved=False)

rows=[]
for r in map(json.loads,(ROOT/'observed-profiles.jsonl').read_text().splitlines()):
    for products in [1,2,math.ceil(1024/(r['ring']//100))]:
        rows.append(derive(r,products))
(ROOT/'derived.json').write_text(json.dumps(rows,indent=2)+'\n')
lines=['# Honest-phase and phase-smoothing diagnostic','',
'Bounds are derived from the inspected 1.3.1 source and exact measured context moduli. Noise observations only check samples against those bounds. No observed maximum is used to choose a bound.',
'', '| p | Dense products summed | Derived final phase bound | Observed phase (one product) | Per-coefficient phase-only bits | Whole-vector phase-only bits | 64-bit vector bound certified? |',
'|---:|---:|---:|---:|---:|---:|---|']
for r in rows:
    lines.append(f"| {r['p']} | {r['products']} | {r['honest_phase_bound']} | {r['observed_phase']} | {r['phase_only_single_coefficient_bits']:.2f} | {r['phase_only_vector_bits']:.2f} | {r['meets_64_vector_bound']} |")
lines+=['','The 13-product row covers the dense-mask products in the L=100,n=1024 final correction at ring 8192. The observed phase column always comes from the separate one-product probe, not a measurement of 13 products.',
'', 'Neither current profile certifies 64-bit whole-vector phase smoothing under this conservative bound. This is failure of this sufficient bound, not proof that the actual statistical distance exceeds 2^-64, and not proof that all other analyses/protocols are impossible.',
'', 'Reducing the flood width by k bits subtracts k from the displayed phase-smoothing budgets. It cannot make a failing bound pass. Repeated objects and key lifetimes require further composition accounting.',
'', 'Even a passing phase-smoothing bound would not establish full ciphertext circuit privacy: the ciphertext includes c1, whose distribution is not randomized by adding noise to c0. A complete argument or a separately justified ciphertext sanitization mechanism is required.',
'', 'A phase threshold is also not a proof of authorized computation. Real-ciphertext tests show zero-phase aggregate substitution and modular doubling returning from a high phase to magnitude one. The proposed attack-detection probability cannot be asserted for arbitrary malicious ciphertexts.']
(ROOT/'RESULTS.md').write_text('\n'.join(lines)+'\n')
print('\n'.join(lines[:12]))
