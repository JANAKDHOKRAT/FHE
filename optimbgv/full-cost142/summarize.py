"""Actual results only. Fail closed for any missing/failed primary configuration."""
import csv,json,math,pathlib,sys
root=pathlib.Path(sys.argv[1]);complete='--complete' in sys.argv
tasks=[('count',1),('sum',1),('histogram',3),('histogram',8)]+[('sumvec',n) for n in [10,25,50,100]]
results=[];missing=[]
def normalize(x):
    if isinstance(x,str):x=json.loads(x)
    return x if isinstance(x,list) else [x]
for task,length in tasks:
    group=[]
    for backend in ['prio','boolean','bgv']:
        if backend=='boolean' and task not in ['count','sumvec']:continue
        name=f'{backend}-{task}-{length}';p=root/(name+'.jsonl');proc=root/(name+'.process.json')
        if not p.exists() or not proc.exists():missing.append(name);continue
        process=json.loads(proc.read_text());rows=[json.loads(x) for x in p.read_text().splitlines()]
        if process['returncode'] or not process['final_pass_record'] or not rows or rows[-1].get('status')!='PASS':
            raise RuntimeError('Failed case: '+name)
        d=rows[-1];assert d['batch_size']==4 and d['task']==task and d['length']==length
        assert normalize(d['actual'])==normalize(d['expected'])
        assert len(d['report_bytes'])==4 and len(set(d['report_bytes']))==1
        if backend=='bgv':
            assert d['p']==65537 and d['ring']==32768
            if task=='sumvec':assert d['aggregate_ciphertexts']==length
        if backend=='boolean':assert d['profile']=='STD128/GINX' and d['bootstrapped_gates']==28*length
        stages=sum(d[k] for k in ['setup_ns','client_total_ns','server_total_ns','collector_total_ns'])
        assert stages<=process['wall_seconds']*1e9+1_000_000,(name,stages,process)
        q={'case':name,'backend':backend,'task':task,'length':length,'batch_size':4,'samples':1,
           'report_bytes':d['report_bytes'][0],'collector_output_bytes':d['aggregate_wire_bytes'],
           'output_ciphertexts':d['aggregate_ciphertexts'],'setup_seconds':d['setup_ns']/1e9,
           'client_batch_seconds':d['client_total_ns']/1e9,'server_batch_seconds':d['server_total_ns']/1e9,
           'collector_batch_seconds':d['collector_total_ns']/1e9,'all_roles_peak_rss_gib':process['process_peak_rss_kib']/1048576,
           'process_wall_seconds':process['wall_seconds'],'process_cpu_seconds':process['user_seconds']+process['system_seconds'],
           'evaluation_key_bytes':d['evaluation_key_bytes'],'public_key_bytes':d['public_key_bytes'],
           'secret_key_bytes':d.get('secret_key_bytes'),'verification_key_bytes':d.get('verification_key_bytes'),
           'expected':normalize(d['expected']),'verified':True}
        results.append(q);group.append(q)
    if len(group)>1:assert all(x['expected']==group[0]['expected'] for x in group)
if complete:assert not missing,missing
summary={'status':'COMPLETE' if not missing else 'IN_PROGRESS','measurements':results,'pending':missing,
         'scope':'one fresh setup and one N=4 batch per case; all roles serial, one thread; no network/DAP wrapper; alternative BGV encodings; no security certificate',
         'boolean_unavailable_complete_tasks':['sum:100','histogram:3','histogram:8']}
(root/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
if results:
    keys=[k for k in results[0] if k!='expected']
    with (root/'measurements.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=keys);writer.writeheader();writer.writerows({k:v for k,v in q.items() if k!='expected'} for q in results)
    lines=['# Full-core cost observations','',summary['scope'],'','Times are seconds per four-report batch; setup is one-time. RSS is whole-process GiB, not isolated server RAM. One diagnostic observation per configuration.','',
      '| Task | Backend | Report B/client | Collector output B/batch | Setup s | Client s/batch | Server s/batch | Collector s/batch | Peak RSS GiB |',
      '|---|---|---:|---:|---:|---:|---:|---:|---:|']
    for q in results:
        label=q['task']+(f"({q['length']})" if q['task'] in ['sumvec','histogram'] else '(100)' if q['task']=='sum' else '')
        lines.append(f"| {label} | {q['backend']} | {q['report_bytes']:,} | {q['collector_output_bytes']:,} | {q['setup_seconds']:.6g} | {q['client_batch_seconds']:.6g} | {q['server_batch_seconds']:.6g} | {q['collector_batch_seconds']:.6g} | {q['all_roles_peak_rss_gib']:.3f} |")
    lines+=['','Boolean Sum/Histogram cells are unavailable: the supplied professor implementation has no complete corresponding validator. No substituted design was benchmarked.','',
      'Prio3 report bytes are public plus both input shares, excluding nonce/HPKE/DAP framing; its raw log separately accounts for duplicated public shares and nonces. FHE reports use their prototype formats. Collector bytes are actual serialized output bundles (or the sum of two Prio3 share messages), excluding transport.','',
      f"Completed {len(results)}/21 configurations; pending: {', '.join(missing) if missing else 'none'}. No stable-throughput, deployment-cost or security-equivalence claim."]
    (root/'MEASUREMENTS.md').write_text('\n'.join(lines)+'\n')
print(json.dumps({'status':summary['status'],'completed':len(results),'pending':missing}))
