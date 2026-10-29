"""Independent ideal-field and public rotation/window schedule checks, not FHE proof."""
from collections import deque,Counter
from math import prod
import heapq,json,itertools
P=65537;N=32768
assert (P-1)%(2*N)==0 and all(P%d for d in range(2,257))
for x in range(P):
 z=(1-pow(x,P-1,P))%P;d=(1-pow(x-1,P-1,P))%P
 assert z==int(x==0) and d==int(x==1) and (z+d)%P==int(x in (0,1))
weights=[1,2,4,8,16,32,37]
assert {sum(w*x for w,x in zip(weights,b)) for b in itertools.product((0,1),repeat=7)}==set(range(101))
for k in (3,8):
 for bits in itertools.product((0,1),repeat=k):
  actual=[int(bits[i]==1)*prod(int(bits[j]==0) for j in range(k) if j!=i) for i in range(k)]
  assert actual==(list(bits) if sum(bits)==1 else [0]*k)
def bfs(keys,bound):
 paths={0:[]};q=deque([0])
 while q:
  u=q.popleft()
  for step in keys:
   v=u+step
   if abs(v)<=bound and v not in paths:paths[v]=paths[u]+[step];q.append(v)
 return paths
plans=[]
for k,keys,budget in [(25,[1,8,-8],11),(50,[-16,-4,-1,1,4,16],7)]:
 paths=bfs(keys,2*k)
 for offset in range(1-k,k):assert sum(paths[offset])==offset and len(paths[offset])+1<=budget
 plans.append({'length':k,'keys':keys,'budget':budget,'all_required_shifts_checked':True})
keys=[1,8,-11];centers=[0,66,-67,-63,70];paths=bfs(keys,200)
for center in centers:
 moves=paths[center];used=0
 for level in range(16):
  count=min(len(moves)-used,7 if level==0 else 6);used+=count
  assert count+(level!=0)<=7
 assert used==len(moves) and sum(moves)==center
# Final implementation: share initial powers, then spread remaining rotations.
maximum=max(len(paths[c]) for c in centers)
rotation_stages=(maximum+5)//6;shared_depth=16-rotation_stages
assert shared_depth>=0
for center in centers:
 used=0
 for level in range(shared_depth,16):
  count=min(6,len(paths[center])-used);used+=count
  assert count+1<=7
 assert used==len(paths[center])
post={c:0 for c in centers};parents={};q=deque(centers)
while q:
 u=q.popleft()
 if post[u]==6:continue
 for step in keys:
  v=u+step
  if abs(v)<=200 and v not in post:post[v]=post[u]+1;parents[v]=(u,step);q.append(v)
for offset in range(-99,100):
 assert post[offset]<=6
 u=offset;net=0;length=0
 while u not in centers:
  u,step=parents[u];net+=step;length+=1
 assert u+net==offset and length+1<=7
for delta in (1,2,4,8,16,32):assert sum(paths[delta])==delta and len(paths[delta])+1<=7
for k in (1,3,7,8,10,25,50,100):
 for selected in range(k):
  coords=[];levels=[17]
  for offset,count in ((-selected,selected),(1,k-selected-1)):
   r=0
   while count:
    if count&1:
     coords.extend(selected+offset+t for t in range(1<<r));levels.append(16+r)
     if k==100:
      center=offset;net=0
      while center not in centers:center,step=parents[center];net+=step
      canonical=Counter(center+t+net for t in range(1<<r))
      assert canonical==Counter(offset+t for t in range(1<<r))
     offset+=1<<r
    count>>=1;r+=1
  assert Counter(coords)==Counter(j for j in range(k) if j!=selected)
  heapq.heapify(levels)
  while len(levels)>1:a=heapq.heappop(levels);b=heapq.heappop(levels);heapq.heappush(levels,max(a,b)+1)
  assert levels[0]==16+k.bit_length()
assert 5*100<P and 5<P
print(json.dumps({'status':'IDEAL_FIELD_AND_SCHEDULE_PASS','field_elements':P,'stock_rotation_plans':plans,'custom100_keys':keys,'custom100_centers':centers,'pre_and_post_budget':7,'all199_shifts_covered':True,'padding_noninterference':'Every selected output reads only the K authorized coordinates; output masks zero other slots.','encrypted_circuit_rerun':False,'noise_failure_bound_proven':False}))
