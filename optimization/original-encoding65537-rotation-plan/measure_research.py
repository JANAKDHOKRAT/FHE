"""One child, actual OS peak RSS/CPU; fail closed without a final PASS record."""
import hashlib,json,os,pathlib,resource,subprocess,sys,time
out=pathlib.Path(sys.argv[1]);err=pathlib.Path(sys.argv[2]);command=sys.argv[3:]
start=time.perf_counter()
with out.open('w') as stdout,err.open('w') as stderr:
    ret=subprocess.run(command,stdout=stdout,stderr=stderr)
usage=resource.getrusage(resource.RUSAGE_CHILDREN)
rows=[]
for line in out.read_text().splitlines():
    try: rows.append(json.loads(line))
    except json.JSONDecodeError: pass
passed=bool(rows and rows[-1].get('status')=='EXPLORATORY_TASK_PASS' and ret.returncode==0)
metrics={'command':command,'returncode':ret.returncode,'final_pass_record':passed,'expected_status':'EXPLORATORY_TASK_PASS',
         'wall_seconds':time.perf_counter()-start,'user_seconds':usage.ru_utime,
         'system_seconds':usage.ru_stime,'process_peak_rss_kib':usage.ru_maxrss,
         'scope':'all simulated roles, setup and diagnostics included; not isolated server RAM'}
out.with_suffix('.process.json').write_text(json.dumps(metrics,indent=2)+'\n')
if not passed:sys.exit(ret.returncode if ret.returncode>0 else 1)
