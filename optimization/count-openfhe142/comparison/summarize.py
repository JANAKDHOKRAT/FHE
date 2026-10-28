from pathlib import Path
import json,statistics
root=Path(__file__).resolve().parent;r=Path('/workspace/fhe-validation/count-openfhe142-2026-10-28')
q=json.loads((r/'qualification.json').read_text());assert q['status']=='scoped compatibility qualification passed'
result={'scope':'Matched original-profile Count implementations on common OpenFHE1.4.2; batch4; same phases and key/context-loading policy. Not a universal scheme/security claim.','qualification':q,'batches':20,'encrypted_reports':80,'backends':{}}
def stat(v):return {'minimum':min(v),'median':statistics.median(v),'maximum':max(v),'samples':v}
for name in ['Boolean','BGV']:
 setups=[];batches=[];ps=[]
 for e in [1,2]:
  rows=[json.loads(x)for x in (r/f'{name}-e{e}.jsonl').read_text().splitlines()];batch=[x for x in rows if x['type']=='batch'];assert len(batch)==5 and sorted(x['run']for x in batch)==[-2,-1,0,1,2]
  assert all(x['correct']and x['actual']==x['expected']and x['n']==4 for x in batch)
  assert all(x['report_bytes']==(8245 if name=='Boolean' else 6176895)for x in batch)
  assert all(x['expected']==(1 if x['run']==-2 else 2)for x in batch)
  if name=='BGV':
   p=next(x for x in rows if x['type']=='parameters');assert p['openfhe']=='1.4.2'and(p['p'],p['n'],p['depth'],p['digits'],p['groups'])==(65537,32768,18,7,4)
  else:assert all(x['gates']==28 for x in batch)
  setups += [x for x in rows if x['type']=='setup'];batches+=batch
  status=json.loads((r/f'{name}-e{e}.stderr').read_text().splitlines()[-1]);assert status['exit_code']==0;ps.append(status)
 measured=[x for x in batches if x['run']>=0];assert len(measured)==6
 for x in measured:
  x['core_s']=(x['decode_ns']+(x['evaluate_ns']if name=='BGV'else x['switch_ns']+x['validate_ns']+x['aggregate_ns']))/1e9
  x['with_init_s']=x['core_s']+x['evaluator_init_ns']/1e9
 d={'report_bytes':measured[0]['report_bytes'],'aggregate_bytes':measured[0]['aggregate_bytes'],'public_key_bytes':setups[0]['public_key_bytes'],'context_bytes':setups[0]['context_bytes'],'evaluation_key_bytes':(setups[0]['mult_key_bytes']+setups[0]['rotation_key_bytes']if name=='BGV'else setups[0]['switch_key_bytes']+setups[0]['bootstrap_key_bytes']),'server_core_s':stat([x['core_s']for x in measured]),'server_with_init_s':stat([x['with_init_s']for x in measured]),'client_per_report_s':stat([x['client_ns']/4/1e9 for x in measured]),'collector_batch_s':stat([x['collector_ns']/1e9 for x in measured]),'combined_measured_stages_s':stat([x['with_init_s']+(x['client_ns']+x['collector_ns'])/1e9 for x in measured]),'epochs':[],'setup':setups,'processes':ps}
 for e in [1,2]:
  a=[x for x in measured if x['epoch']==e];d['epochs'].append({'epoch':e,'core_median_s':statistics.median(x['core_s']for x in a),'with_init_median_s':statistics.median(x['with_init_s']for x in a)})
 result['backends'][name]=d
(r/'matched-summary.json').write_text(json.dumps(result,indent=2)+'\n')
B=result['backends'];fmt=lambda v:f'{v:.3f}'
text='''# Matched Count comparison on OpenFHE1.4.2

Original professor source and1.4.2 build preserved. A separate benchmark adapter retains STD128/GINX and the identical four-gate scalar Count validator/mask and incremental counter (28 gates/batch4). BGV uses the separate1.4.2 port, with original p65537,ring32768,depth18,digits7,groups4,cap32,exact Count projection. Its full Q/QP profile and6176895-byte reports are unchanged.

Both use the same installed1.4.2 SDK, same host/CPU0/one thread, same four plaintexts, two fresh-key epochs, identical invalid qualification/warmup/three measured valid batches per epoch, and matched timing phases. Both deserialize context/public and evaluation material per batch; separate initialization and core columns prevent confusing key loading with circuit cost. This scenario is explicitly per-batch evaluator creation, not a claim that reloading every batch is optimal deployment caching. Original untouched professor CLI is a baseline; this adapter supplies instrumentation.

**20 batches /80 encrypted reports passed**. Valid[0,1,0,1] gives2; invalid-input[0,1,2,3] gives1; all Boolean diagnostic flags/digits checked outside measured server time, and every BGV scalar compared to expected. Primary data excludes the earlier adapter smoke run and qualification stress-test timings.

| Measured quantity | Original Boolean parameters | Small BGV Count parameters |
|---|---:|---:|
'''
for label,key in [('Report bytes','report_bytes'),('Public-key bytes','public_key_bytes'),('All evaluation-key bytes','evaluation_key_bytes'),('Output aggregate bytes','aggregate_bytes')]:text+=f"| {label} | {B['Boolean'][key]:,} | {B['BGV'][key]:,} |\n"
for key,label in [('server_core_s','Server core seconds/batch, six-sample median'),('server_with_init_s','Server incl. batch initialization seconds, median'),('client_per_report_s','Client encryption+encoding+serialization seconds/report, median'),('collector_batch_s','Collector decoding+decryption seconds/batch, median'),('combined_measured_stages_s','Combined measured client+server-init+core+collector seconds/batch, median')]:text+=f"| {label} | {B['Boolean'][key]['median']:.6f} | {B['BGV'][key]['median']:.6f} |\n"
text+='\n## Per-key medians and ranges\n\n'
for name in ['Boolean','BGV']:
 d=B[name];text+=f"- {name}: core medians key1/key2 {' / '.join(fmt(x['core_median_s'])for x in d['epochs'])}s; with initialization {' / '.join(fmt(x['with_init_median_s'])for x in d['epochs'])}s. Observed core range {d['server_core_s']['minimum']:.3f}–{d['server_core_s']['maximum']:.3f}s; with-init range {d['server_with_init_s']['minimum']:.3f}–{d['server_with_init_s']['maximum']:.3f}s. Whole-process peak RSS {max(x['max_rss_kib']for x in d['processes'])/1048576:.3f}GiB.\n"
text+='''
Server core includes report decoding, admission/conversion, validation/masking, aggregation and output serialization. Client and collector phases measured separately. No network, transport authentication or release-wrapper cost. Whole-process RSS includes all roles, key generation, serialization, codec qualification and material loading; it is not isolated server RAM. Stage sums exclude lifecycle cleanup; whole-process wall/CPU/RSS retained separately. SDK native library compilation is common; Rust/C++ adapter and shim compiler flags are recorded, so this is a concrete implementation comparison, not an algorithmic lower bound or proof of optimal tuning.

BGV startup includes mandatory native codec qualification; Boolean setup includes original public bootstrapping-key generation and encrypted constants. Setup raw fields retained in matched-summary.json. Diagnostic decryptions outside timing. Six measured batches share two keys, so no independent-sample confidence interval or broad failure-rate claim is made.

The requested nominal library security criterion is retained. Separate prior generic-lattice screening remains BGV ADPS16~97.24/MATZOV~130.24 and original Boolean ADPS16~97.53/MATZOV~120.92. A successful port/benchmark is not a128-bit protocol-security certificate. Arbitrary-ciphertext security and collector circuit privacy remain unproven. Count output equivalence does not expose an independent BGV validity flag. Boolean Z4 and BGV F65537 input spaces differ; common tested input domain0..3 and final Count disclosure are matched.

Count only, batch4 measurement; no vector-length crossover claim. The Count port additionally passed all batch boundaries1..32 and output-slot checks in separate correctness tests. Original1.3.1 code, professor artifact and previous experiments preserved. No automatic commit or push.
'''
hardware=json.loads((r/'matched-environment.json').read_text())
model=next((line.split(':',1)[1].strip()for line in hardware['cpu'].splitlines()if line.startswith('Model name:')),'see matched-environment.json')
text+=f"\n## Host and setup accounting\n\nHost: {model}; VM CPU quota {hardware['cgroup_cpu'].strip()}, memory limit {hardware['cgroup_memory'].strip()} bytes. Both ran on CPU0 with one thread. This restored workspace has a different processor from earlier Xeon-based experiments; those old runtimes are not mixed into this table.\n"
for name in ['Boolean','BGV']:
 d=B[name];values=[]
 for x in d['setup']:
  fields=['task_init_ns','setup_including_key_serialize_ns','client_init_ns','collector_init_ns']if name=='BGV'else['setup_ns','key_serialize_ns','constants_ns']
  values.append(sum(x[f]for f in fields)/1e9)
 text+=f"\n- {name}: one-time measured setup stages key1/key2 {' / '.join(f'{v:.3f}'for v in values)}s. Raw fields retained so native codec qualification and key serialization are not hidden.\n"
text+="\nCombined stage sums are not network end-to-end latency: process cleanup, communication and transport are excluded. Setup scopes differ because BGV's own required codec qualification is additional implementation work; it remains enabled.\n\nThe1.4.2 BGV evaluation-key serialization is24bytes smaller in total than the retained1.3.1 sample (8bytes per key). Upstream EvalKeyRelin changed from an outer vector-of-vectors to separately serialized A/B vectors. Full mathematical Q/QP parameters and the client report are unchanged. Do not reuse1.3.1 serialized evaluation keys as if the schemas were identical; this port uses fresh1.4.2 setup and does not certify cross-version state migration.\n"
(r/'MATCHED-RESULTS.md').write_text(text);print(text)
