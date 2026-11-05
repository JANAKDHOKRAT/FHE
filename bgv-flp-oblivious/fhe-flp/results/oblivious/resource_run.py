"""Linux wait4 accounting for a single benchmark process; no GNU time needed."""
import os, subprocess, sys
p=subprocess.Popen(sys.argv[1:])
_,status,usage=os.wait4(p.pid,0)
p.returncode=os.waitstatus_to_exitcode(status)
print(f'PEAK_RSS_KIB={usage.ru_maxrss}',file=sys.stderr)
sys.exit(p.returncode if p.returncode>=0 else 128-p.returncode)
