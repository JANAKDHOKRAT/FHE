import subprocess,resource,time,sys,json
start=time.monotonic_ns();proc=subprocess.run(sys.argv[1:]);r=resource.getrusage(resource.RUSAGE_CHILDREN)
print(json.dumps({'process_measurement':True,'wall_ns':time.monotonic_ns()-start,'user_seconds':r.ru_utime,'system_seconds':r.ru_stime,'max_rss_kib':r.ru_maxrss,'exit_code':proc.returncode}),file=sys.stderr,flush=True)
sys.exit(proc.returncode)
