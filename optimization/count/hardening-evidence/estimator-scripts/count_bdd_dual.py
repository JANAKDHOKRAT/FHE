import json,math,time,struct,multiprocessing
from sage.all import ZZ,oo,log
from estimator import LWE,ND,RC
row=next(r for r in json.load(open('count_hardening_profiles.json')) if r['name']=='projected-786433-d4')
q=math.prod(map(int,row['qp_moduli']));sigma=struct.unpack('f',struct.pack('f',3.19))[0]
params=LWE.Parameters(n=row['n'],q=ZZ(q),Xs=ND.Uniform(-1,1),Xe=ND.DiscreteGaussian(sigma),m=oo,tag=row['name'])
def worker(send,fn,model):
 try:
  c=fn(params,red_cost_model=model);send.send({'status':'completed','log2_rop':float(log(c['rop'],2)),'cost':str(c)})
 except Exception as e:send.send({'status':'error','error':repr(e)})
for label,model in [('ADPS16',RC.ADPS16),('MATZOV',RC.MATZOV)]:
 for name,fn in [('bdd',LWE.primal_bdd),('dual',LWE.dual)]:
  print('START',name,label,flush=True);recv,send=multiprocessing.Pipe(False);p=multiprocessing.Process(target=worker,args=(send,fn,model));t=time.monotonic();p.start();p.join(90)
  if p.is_alive():p.terminate();p.join();res={'status':'timed_out','limit_seconds':90}
  elif recv.poll():res=recv.recv()
  else:res={'status':'worker_failed','exitcode':p.exitcode}
  print('RESULT_JSON '+json.dumps({'profile':row['name'],'model':label,'algorithm':name,'seconds':time.monotonic()-t,**res}),flush=True)
