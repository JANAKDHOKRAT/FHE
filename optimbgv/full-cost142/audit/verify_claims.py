#!/usr/bin/env python3
"""Standalone integer/evidence audit. No OpenFHE imports or security-estimator claims.
Run from any directory; Python 3 standard library only. Fails on any assertion.
Checksums detect changes relative to the manifest, not fabricated original data.
"""
import csv
import hashlib
import json
import math
import pathlib
import re

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
EVIDENCE = HERE.parent / 'evidence'
P, N = 65537, 32768


def prime(n):
    if n < 2:
        return False
    for d in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]:
        if n % d == 0:
            return n == d
    assert n < 2**64
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    # Deterministic Miller-Rabin bases for unsigned 64-bit integers.
    for a in [2, 325, 9375, 28178, 450775, 9780504, 1795265022]:
        x = pow(a % n, d, n)
        if a % n == 0 or x in [1, n - 1]:
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def bit(i, j):
    return (17*i + 31*j + j//3 + i*j//7) % 2


def norm(x):
    if isinstance(x, str):
        x = json.loads(x)
    return x if isinstance(x, list) else [x]


def delta(x, a):
    return (1 - pow((x-a) % P, P-1, P)) % P


def verify_hashes():
    manifest = HERE / 'SHA256SUMS.txt'
    assert manifest.is_file(), 'Missing audit manifest'
    for line in manifest.read_text().splitlines():
        digest, rel = line.split('  ', 1)
        path = ROOT / rel
        assert path.is_relative_to(ROOT) and '..' not in pathlib.Path(rel).parts
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest, rel


verify_hashes()
assert prime(P) and (P-1) % (2*N) == 0
assert (P-1) % (2*65536) != 0
assert P-1 == 2**16
# Exhaustive field check: both Count polynomials, including invalid values.
for x in range(P):
    old = x * (1 - pow(x*(x-1) % P, P-1, P)) % P
    new = delta(x, 1)
    assert old == new == int(x == 1)
    assert delta(x, 0) == int(x == 0)
# Evaluate the full weighted Sum polynomial, not just its claimed closed form.
for x in range(P):
    got = sum(a * delta(x, a) for a in range(1, 101)) % P
    assert got == (x if x <= 100 else 0)
    for buckets in [3, 8]:
        got = [delta(x, a) for a in range(buckets)]
        assert got == [int(x == a) for a in range(buckets)]
# All canonical chunks and subset-table columns; equality identity above supplies
# the all-field membership proof. This does NOT enumerate every vector in F_p^m.
columns = 0
for width in range(1, 14):
    domain = 1 << width
    assert domain <= N//2 and (N//2) % domain == 0
    for k in range(width):
        table = [a for a in range(domain) if (a >> k) & 1]
        assert len(table) == domain//2 and 0 not in table
        assert len(set(table)) == len(table)
        assert all(a < domain for a in table)
        columns += len(table)
    for x in range(domain):
        assert sum(((x >> k) & 1) << k for k in range(width)) == x
# Whole-report gate truth tables, all possible valid/invalid chunk patterns.
gate_patterns = 0
for length in [10, 25, 50, 100]:
    m = (length+12)//13
    for mask in range(1 << m):
        valid = [(mask >> h) & 1 for h in range(m)]
        for h in range(m):
            # D is arbitrary 0/1 for valid chunks, identically 0 for invalid.
            for d in range(valid[h]+1):
                got = d * math.prod(valid[j] for j in range(m) if j != h)
                assert got == (d if all(valid) else 0)
        gate_patterns += 1
# Count fixture also supplies parameters absent from the Count cost log.
fixture = (ROOT/'count-openfhe142/fhe-paper-core/tests/fixtures/count142_profile.rs').read_text()
arrays = {}
for key in ['Q', 'QP']:
    body = re.search(r'pub const '+key+r':.*?= &\[(.*?)\];', fixture, re.S).group(1)
    arrays[key.lower()] = [int(x) for x in re.findall(r'\d+', body)]
profiles, completed = [], []
csv_rows = {r['case']: r for r in csv.DictReader((EVIDENCE/'measurements.csv').open())}
assert len(csv_rows) == 21
for task, length in [('count',1),('sum',1),('histogram',3),('histogram',8)]+[('sumvec',l) for l in [10,25,50,100]]:
    oracle = ([sum(bit(i,0) for i in range(4))] if task=='count' else
              [200] if task=='sum' else
              [sum(i % length == j for i in range(4)) for j in range(length)] if task=='histogram' else
              [sum(bit(i,j) for i in range(4)) for j in range(length)])
    for backend in ['prio','boolean','bgv']:
        if backend=='boolean' and task not in ['count','sumvec']:
            continue
        name=f'{backend}-{task}-{length}'
        records=[json.loads(l) for l in (EVIDENCE/(name+'.jsonl')).read_text().splitlines()]
        d=records[-1]
        process=json.loads((EVIDENCE/(name+'.process.json')).read_text())
        assert process['returncode']==0 and process['final_pass_record']
        assert d['status']=='PASS' and d['batch_size']==4
        assert norm(d['actual'])==norm(d['expected'])==oracle
        assert len(d['report_bytes'])==4 and len(set(d['report_bytes']))==1
        assert sum(d[k] for k in ['setup_ns','client_total_ns','server_total_ns','collector_total_ns']) <= process['wall_seconds']*1e9+1e6
        assert process['process_peak_rss_kib'] > 0
        if backend=='boolean':
            assert d['profile']=='STD128/GINX'
            assert d['bootstrapped_gates']==28*length
            assert d['aggregate_ciphertexts']==3*length
            assert d['report_bytes'][0]==21+8224*length
            assert d['aggregate_wire_bytes'] == (12189 if length==1 else 21+12176*length)
        if backend=='bgv':
            assert d['p']==P and d['ring']==N
            setup=arrays if task=='count' else records[0]
            q,qp=setup['q'],setup['qp']
            assert len(set(qp))==len(qp) and qp[:len(q)]==q
            assert all(prime(t) and (t-1) % (2*N)==0 for t in qp)
            bits=sum(t.bit_length() for t in q)
            assert d['report_bytes'][0]==127+(2*N*bits+7)//8
            m=(length+12)//13 if task=='sumvec' else 1
            required=17+(m-1).bit_length() if task=='sumvec' else 18
            assert d['depth']==max(18,required)
            assert d['digits']==(7 if required<=18 else required+2)
            if required <= 18:
                assert q == arrays['q'] and qp == arrays['qp']
            assert d['aggregate_ciphertexts']==(length if task=='sumvec' else 1)
            if task=='sumvec':
                assert d['square_calls']==4*16*(length+m)
                assert d['ciphertext_multiply_calls']==4*length*(m-1)
            if task!='count':
                assert d['evaluation_key_bytes']==setup['rotation_key_bytes']+setup['mult_key_bytes']
                assert sum(d['aggregate_parts_bytes'])==d['aggregate_ciphertext_bytes_sum']
                assert len(d['aggregate_parts_bytes'])==d['aggregate_ciphertexts']
            assert (4*100 if task=='sum' else 4)<P
            profiles.append({'task':task,'length':length,'q':q,'qp':qp,
                             'q_storage_bits_per_coefficient':bits,
                             'log2_Q':sum(math.log2(t) for t in q),
                             'log2_QP':sum(math.log2(t) for t in qp),
                             'depth':d['depth'],'digits':d['digits'],
                             'report_bytes':d['report_bytes'][0]})
        published = csv_rows[name]
        for field, want in [('report_bytes',d['report_bytes'][0]),
                            ('collector_output_bytes',d['aggregate_wire_bytes']),
                            ('evaluation_key_bytes',d['evaluation_key_bytes']),
                            ('public_key_bytes',d['public_key_bytes']),
                            ('output_ciphertexts',d['aggregate_ciphertexts'])]:
            assert int(published[field]) == want, (name, field)
        for field, raw in [('setup_seconds','setup_ns'),('client_batch_seconds','client_total_ns'),
                           ('server_batch_seconds','server_total_ns'),('collector_batch_seconds','collector_total_ns')]:
            assert math.isclose(float(published[field]),d[raw]/1e9,rel_tol=1e-12), (name,field)
        assert math.isclose(float(published['all_roles_peak_rss_gib']),process['process_peak_rss_kib']/1048576,rel_tol=1e-12)
        completed.append(name)
assert len(completed)==21
print(json.dumps({'status':'AUDIT_PASS','encrypted_circuits_rerun':False,
 'security_estimator_rerun':False,'security_certified':False,
 'field_values_exhausted':P,'sum_polynomial_terms_per_input':100,
 'subset_table_entries_checked':columns,'all_chunk_validity_patterns':gate_patterns,
 'completed_cases':completed,'bgv_profiles':profiles},indent=2))
