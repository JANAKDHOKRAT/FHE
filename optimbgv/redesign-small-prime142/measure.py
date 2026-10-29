"""Capture a single subprocess's logs and OS resource measurements (Linux)."""
import json
import pathlib
import resource
import subprocess
import sys
import time

out=pathlib.Path(sys.argv[1]);err=pathlib.Path(sys.argv[2]);command=sys.argv[3:]
start=time.perf_counter()
with out.open('w') as stdout,err.open('w') as stderr:
    ret=subprocess.run(command,stdout=stdout,stderr=stderr)
usage=resource.getrusage(resource.RUSAGE_CHILDREN)
out.with_suffix('.process.json').write_text(json.dumps({
    'command':command,'returncode':ret.returncode,'wall_seconds':time.perf_counter()-start,
    'user_seconds':usage.ru_utime,'system_seconds':usage.ru_stime,
    'process_peak_rss_kib':usage.ru_maxrss},indent=2)+'\n')
sys.exit(ret.returncode if ret.returncode>=0 else 128-ret.returncode)
