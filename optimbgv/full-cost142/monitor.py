"""Read-only progress monitor, no crypto work."""
import json,pathlib,sys,time
r=pathlib.Path(sys.argv[1]);last=None
while True:
    p=r/'exits.jsonl';rows=[json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []
    running=[]
    for f in r.glob('*.jsonl'):
        if f.name=='exits.jsonl':continue
        lines=f.read_text().splitlines()
        if not lines:continue
        try:d=json.loads(lines[-1])
        except json.JSONDecodeError:continue
        if d.get('status')!='PASS':running.append((f.stem,d.get('status'),d.get('report'),d.get('chunk'),d.get('bit_or_validity')))
    state=(len(rows),tuple(running))
    if state!=last:print(json.dumps({'completed':len(rows),'current':running}),flush=True);last=state
    if any(x['exit'] for x in rows) or len(rows)>=21:break
    time.sleep(20)
