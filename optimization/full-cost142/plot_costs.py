"""Publication-exportable plots of actual completed observations; no extrapolation."""
import csv,pathlib,sys
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

root=pathlib.Path(sys.argv[1]);rows=list(csv.DictReader((root/'measurements.csv').open()))
assert len(rows)==21,'Plot only the complete declared matrix'
tasks=[('count',1),('sum',1),('histogram',3),('histogram',8)]+[('sumvec',l) for l in [10,25,50,100]]
labels=['Count','Sum(100)','Hist(3)','Hist(8)','Vec(10)','Vec(25)','Vec(50)','Vec(100)']
data={(r['backend'],r['task'],int(r['length'])):r for r in rows}
colors={'prio':'#2878B5','boolean':'#D77B20','bgv':'#31915C'}
names={'prio':'Prio3','boolean':'Professor Boolean (STD128)','bgv':'Small-prime BGV'}
fig,axes=plt.subplots(2,2,figsize=(13,8.2))
panels=[('server_batch_seconds',1,'Evaluator time per four-report batch (s)'),
        ('collector_output_bytes',1,'Serialized collector output per batch (bytes)'),
        ('setup_seconds',1,'One-time fresh-process setup (s)'),
        ('all_roles_peak_rss_gib',1024,'Whole-process peak RSS (MiB)')]
for ax,(field,scale,title) in zip(axes.flat,panels):
    for i,backend in enumerate(['prio','boolean','bgv']):
        xs=[];ys=[]
        for j,(task,length) in enumerate(tasks):
            if (backend,task,length) not in data:continue
            value=float(data[backend,task,length][field])*scale;assert value>0
            xs.append(j+(i-1)*.24);ys.append(value)
        ax.bar(xs,ys,width=.22,color=colors[backend],zorder=3)
    ax.set_yscale('log');ax.set_xticks(range(len(labels)),labels,rotation=22,ha='right')
    ax.set_title(title,fontsize=11);ax.grid(True,axis='y',which='major',alpha=.25,zorder=0)
fig.suptitle('Full core-cost observations: one fresh setup + one valid N=4 batch per configuration',fontsize=12)
fig.legend([Patch(color=colors[b]) for b in colors],[names[b] for b in colors],loc='upper center',bbox_to_anchor=(.5,.955),ncol=3,frameon=False)
fig.text(.5,.015,'Same host, CPU0, one thread. Logarithmic axes; one diagnostic run, no confidence intervals.\n'
         'RSS includes all simulated roles/setup/diagnostics. Formats differ; network/DAP wrappers excluded.\n'
         'Missing Boolean Sum/Histogram bars mean no supplied complete implementation, not zero cost.',ha='center',fontsize=8)
fig.tight_layout(rect=(0,.085,1,.91))
fig.savefig(root/'full-cost.pdf',bbox_inches='tight');fig.savefig(root/'full-cost.png',dpi=180,bbox_inches='tight')
print(root/'full-cost.pdf')
