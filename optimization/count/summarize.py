#!/usr/bin/env python3
"""Validate recorded evidence; never promote a local pass to a security proof."""
import argparse,hashlib,json,pathlib,math,tarfile
R=pathlib.Path(__file__).resolve().parent;E=R/'evidence'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 global E
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--evidence',type=pathlib.Path,default=E);E=ap.parse_args().evidence.resolve()
 m=json.loads((E/'manifest.json').read_text());assert m['status']=='completed',m['status']
 inventory=json.loads((E/'source-sha256.json').read_text())
 with tarfile.open(E/'source.tar.gz','r:gz') as archive:
  members={x.name:x for x in archive.getmembers() if x.isfile()}
  assert set(members)==set(inventory)
  for name,want in inventory.items():assert hashlib.sha256(archive.extractfile(members[name]).read()).hexdigest()==want
 assert len(m['profiles'])==5 and len(m['runs'])==10
 assert m['algebra']['returncode']==0 and sha(R/m['algebra']['log'])==m['algebra']['sha256']
 for p in m['profiles'].values():assert p['returncode']==0 and sha(R/p['log'])==p['sha256']
 grouped={};batches=reports=0
 for r in m['runs']:
  assert r['returncode']==0 and sha(R/r['log'])==r['sha256']
  f=E/r['profile']/f"key-{r['key']}.json";assert sha(f)==r['measurement_sha256'];d=json.loads(f.read_text())
  expected={'baseline-g4':(786433,2,False,4,4),'projected-large-g4':(786433,2,True,4,4),'projected-small-g4':(65537,7,True,4,4),'projected-small-full':(65537,7,True,16384,4),'projected-small-g32':(65537,7,True,32,32)}
  assert (d['plain_mod'],d['key_switch_digits'],d['count_projection'],d['reports_per_verification_ciphertext'],d['reports_per_batch'])==expected[r['profile']]
  assert d['type']=='count'  and d['check']=='exact' and d['key_mode']=='native-single'
  assert d['batches']==3 and d['max_batch']==32 and d['security_bits']==128 and d['secret_distribution']=='UNIFORM_TERNARY'
  assert (d['plain_mod']-1)%(2*d['ring_dim'])==0
  assert d['reports_per_batch']<=32<d['plain_mod']
  assert d['mult_depth']==int(math.log2(d['plain_mod']-1))+(d['plain_mod']-1).bit_count()-1+(2 if d['count_projection'] else 4)
  q=[int(p) for p in d['q_moduli_decimal']]
  assert d['report_bytes']==56+(2*d['ring_dim']*sum((qj-1).bit_length() for qj in q)+7)//8
  qp=[int(p) for p in d['key_switch_moduli_decimal']]
  bound={32768:881,65536:1747}[d['ring_dim']]
  # Strict integer comparison with pinned OpenFHE ternary/classic-128 table.
  assert math.prod(qp)<(1<<bound),(r['profile'],'QP exceeds pinned table')
  assert len(d['evaluator_total_per_batch_ms'])==3
  reports+=d['batches']*d['reports_per_batch'];batches+=d['batches']
  grouped.setdefault(r['profile'],[]).append(d)
 lines=['# Measured Count experiment','', 'All figures below are measurements, not the earlier 50% estimate.','', '| Profile | Ring | Depth | Serialized report MiB | Eval keys MiB | Median evaluator seconds/report, by fresh key | Peak RSS GiB |','|---|---:|---:|---:|---:|---|---:|']
 for name,ds in grouped.items():
  a=ds[0];assert len(ds)==2
  for k in ['ring_dim','mult_depth','report_bytes','rotation_key_bytes','eval_mult_key_bytes']:assert a[k]==ds[1][k]
  keys=a['rotation_key_bytes']+a['eval_mult_key_bytes'];times=', '.join(f"{d['evaluator_total_per_report']['median_ms']/1000:.3f}" for d in ds)
  lines.append(f"| {name} | {a['ring_dim']} | {a['mult_depth']} | {a['serialized_report_bytes']/2**20:.3f} | {keys/2**20:.3f} | {times} | {max(d['peak_rss_kb'] for d in ds)/2**20:.3f} |")
 base=grouped['baseline-g4'][0]['serialized_report_bytes'];new=grouped['projected-small-g4'][0]['serialized_report_bytes']
 lines += ['',f'Full serialized report: {base:,} -> {new:,} bytes; measured reduction {100*(1-new/base):.3f}%.','Packed size is independently checked as 56 + ceil(2*n*sum(bitlen(q_j-1))/8) bytes from recorded ring and Q primes. Packed ciphertext bytes exclude the report envelope; serialized_report_bytes includes it. Neither includes an unspecified network transport.',f'{batches} timed batches, {reports} reports; every benchmark batch checked against plaintext.', '', 'Two fresh keys per profile, three batches per key. These are small samples; no population speedup or independent-sample confidence claim is made. API setup_ms excludes native planning; wall_s covers the process. Lower seconds/report at N=32 is amortized batch throughput, not single-client latency.', '', 'Encryption parameters satisfy the pinned OpenFHE 1.3.1 ternary/classic-128 table including auxiliary QP. This is a table consistency check, not an independent lattice estimate or protocol-security proof.', '', '**Production gate: NOT GREEN.** Replay, arbitrary-ciphertext security, authenticated aggregate provenance, output-only disclosure and network/concurrency resource controls are not established. See ATTACKS.md. No production push is authorized by these local passes.']
 if (E/'gate.json').exists():
  gate=json.loads((E/'gate.json').read_text());log=E/'supplementary.log'
  assert sha(log)==gate['logs_sha256']['supplementary.log']
  text=log.read_text();assert all(f'BOUNDARY N={n} all-one batch correct' in text for n in range(1,33))
  assert all(f'STRESS case={n} N=32 output=0' in text for n in range(4))
  assert 'test result: ok. 1 passed' in text and 'test result: ok. 2 passed' in text
  lines += ['', 'Supplementary tests passed for every all-one batch size 1–32, with all other slots in both rows zero; four extra 32-report batches covered zero, p−1, p/2 and deterministic random nonbits. Wrong-key and 64 malformed submissions were refused in the tested cases. Aggregate substitution and direct collector decryption were reproduced as declared trust limitations. See evidence/supplementary.log and evidence/gate.json.']
 (R/'RESULTS.md').write_text('\n'.join(lines)+'\n');print('\n'.join(lines))
if __name__=='__main__':main()
