import json, pathlib, re
root=pathlib.Path(__file__).resolve().parent
rows=[json.loads(l) for l in (root/'measurements.jsonl').read_text().splitlines()]
pairs={}
for r in rows:
    if r.get('exit_code')==0:pairs.setdefault((r['reports'],r['field'],tuple(r['case'])),{})[r['mode']]=r
lines=['# Matched encrypted-verdict measurements','',
'One trial per configuration, OpenFHE 1.3.1, release build, OMP_NUM_THREADS=2. Both executables assert the decoded result equals the plaintext reference. These historical runs predate the implemented phase guard; its overhead is excluded. No statistical speed claim is justified.',
'', 'Times below cover client encryption, ingest, evaluator check, collector check (including verdict encryption for the new flow), final evaluator work, and collector decoding. They exclude task/key setup. RSS is the per-process wait4 high-water mark; process wall time and setup timings remain in raw JSON.',
'', '| n | Field | Task | Client B (both) | Check total B, baseline → new | Reply B, baseline → new | Final B, baseline → new | Core seconds, baseline → new | New/base core | Peak MiB, baseline → new |','|---:|---|---|---:|---|---|---|---|---:|---|']
summary=[]
def seconds(m,n):return (sum(m[x]*n for x in ['client_ms','evaluator_ingest_ms','evaluator_check_ms','collector_check_ms'])+m['evaluator_aggregate_ms']+m['collector_unshard_ms'])/1000
for (n,field,case),p in pairs.items():
    if len(p)!=2:continue
    b=p['measure_single'];v=p['measure_oblivious'];bm=b['measurement'];vm=v['measurement']
    report,check,reply,final=map(int,re.search(r'WIRE_TOTALS report=(\d+) check=(\d+) reply=(\d+) final=(\d+)',v['stderr']).groups())
    oldcheck=4+n*bm['check_request_bytes_per_report'];oldreply=(n+7)//8;oldfinal=bm['aggregate_request_bytes']
    reduced=oldfinal-8
    extra=(case[0]=='sum' or (case[0]=='sumvec' and case[-1]!='1'))
    assert report==bm['report_bytes']==vm['report_bytes']
    assert check-oldcheck==68+32*n+int(extra)*n*reduced
    assert final-oldfinal==64
    L=int(case[case.index('--len')+1]) if '--len' in case else 1
    per=bm['ring']//L;blocks=(n+per-1)//per
    fresh=(report-16)//bm['ciphertexts_per_report']
    assert reply==72+blocks*fresh
    bt,vt=seconds(bm,n),seconds(vm,n)
    br=int(re.search(r'PEAK_RSS_KIB=(\d+)',b['stderr']).group(1))/1024
    vr=int(re.search(r'PEAK_RSS_KIB=(\d+)',v['stderr']).group(1))/1024
    name=bm['type']
    lines.append(f'| {n} | {field} | {name} | {report:,} | {oldcheck:,} → {check:,} | {oldreply:,} → {reply:,} | {oldfinal:,} → {final:,} | {bt:.3f} → {vt:.3f} | {vt/bt:.3f} | {br:.1f} → {vr:.1f} |')
    summary.append(dict(n=n,field=field,task=name,report_bytes=report,check_baseline=oldcheck,check_new=check,reply_baseline=oldreply,reply_new=reply,final_baseline=oldfinal,final_new=final,core_baseline_s=bt,core_new_s=vt,core_ratio=vt/bt,rss_baseline_mib=br,rss_new_mib=vr,wire_prediction_pass=True))
failed=[r for r in rows if r.get('exit_code')!=0]
lines+=['',f'Completed raw runs: {len(rows)}. Failed raw runs: {len(failed)}. Matched successful comparisons: {len(summary)}.',
'', 'All recorded successful wire sizes match the predeclared formulas. The 32-byte per-report digest and versioned headers are included. Binary SumVec(max=1) follows Select, so it adds no output ciphertext.',
'', 'This is the completed pre-phase-guard matrix at 16/256/1024 reports. It does not measure the current guard.',
'', 'Preserve this historical dataset before running the current code and generating a new summary. It can take substantial time and memory; resource failures must remain in the data. Sum(100) at p=65537 does not support 1024 reports (max 655).',
'', 'Production gate: NOT GREEN. Rigorous flooding/phase bounds, constant-time/error-channel behavior, the T5 gate test, portable task encoding and deployment resource policies remain unresolved.']
(root/'RESULTS.md').write_text('\n'.join(lines)+'\n')
(root/'summary.json').write_text(json.dumps(summary,indent=2))
print('\n'.join(lines[:10]));print('comparisons',len(summary),'failed',len(failed))
