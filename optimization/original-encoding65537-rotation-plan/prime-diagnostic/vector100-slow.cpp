// Original coordinates, exact full-report contribution. No lookup encoding.
#include "../native_checks.h"
#include "../packed.h"
#include <chrono>
#include <fstream>
#include <numeric>
#include <queue>
#include <map>
#include <set>
#include <functional>
using Clock=std::chrono::steady_clock;
int main(int argc,char**argv){try{
 require(argc==3,"usage: exact TASK LENGTH");std::string task=argv[1];unsigned K=std::stoul(argv[2]);require((task=="sum"&&K==7)||(task=="histogram"&&K==8)||(task=="sumvec"&&(K==25||K==50||K==100)),"unsupported task");
 require(task=="sumvec"&&K==100,"isolated 100-bit research only");
 std::vector<int32_t> indices={-16,-1,1,16};
 std::map<int,std::vector<int>> paths;std::queue<int> queue;paths[0]={};queue.push(0);
 while(!queue.empty()){int u=queue.front();queue.pop();for(int v:indices){int w=u+v;if(std::abs(w)<=int(2*K)&&!paths.count(w)){paths[w]=paths[u];paths[w].push_back(v);queue.push(w);}}}
 std::set<int> uncovered;for(int i=1-int(K);i<int(K);i++)uncovered.insert(i);
 std::vector<int> centers;std::map<int,int> assigned;
 auto cover=[&](int center){centers.push_back(center);for(int step:std::vector<int>{0,-16,-1,1,16})if(uncovered.erase(center+step))assigned[center+step]=center;};
 cover(0);
 while(!uncovered.empty()){int best=0;size_t score=0;for(int center=-int(K)-16;center<=int(K)+16;center++)if(paths.at(center).size()<=16){size_t count=0;for(int step:std::vector<int>{0,-16,-1,1,16})count+=uncovered.count(center+step);if(count>score){score=count;best=center;}}require(score>0,"cover failed");cover(best);}
 unsigned maxpath=0;for(int center:centers)maxpath=std::max(maxpath,unsigned(paths.at(center).size()));require(maxpath<=16,"too many rotation stages");unsigned base=16-maxpath;unsigned switches=2;
 unsigned depth=16;for(unsigned v=K;v;v>>=1)depth++; // 16+ceil(log2(K+1)) includes one selected-D mask
 CCParams<CryptoContextBGVRNS> p;p.SetPlaintextModulus(65537);p.SetRingDim(32768);p.SetMultiplicativeDepth(depth);p.SetSecurityLevel(HEStd_128_classic);p.SetSecretKeyDist(UNIFORM_TERNARY);p.SetMultipartyMode(FIXED_NOISE_MULTIPARTY);p.SetScalingTechnique(FLEXIBLEAUTOEXT);p.SetKeySwitchTechnique(BV);p.SetDigitSize(10);p.SetEvalAddCount(task=="histogram"?0:1);p.SetKeySwitchCount(switches);
 auto start=Clock::now();auto c=GenCryptoContext(p);require(c->GetRingDimension()==32768,"ring mismatch");c->Enable(PKE);c->Enable(KEYSWITCH);c->Enable(LEVELEDSHE);c->Enable(ADVANCEDSHE);
 std::cout<<"{\"status\":\"PARAMETERS_ONLY\",\"task\":"<<std::quoted(task)<<",\"length\":"<<K<<",\"depth\":"<<depth<<",\"digit\":10,\"switches\":"<<switches<<",\"p\":65537,\"ring\":32768}"<<std::endl;
 std::ifstream libraries("/proc/self/maps");std::string loaded;unsigned seen=0;while(std::getline(libraries,loaded))if(loaded.find("libOPENFHE")!=std::string::npos){require(loaded.find("/workspace/fhe-deps/install-bound-prime-study/lib/")!=std::string::npos,"mixed SDK");seen++;}require(seen>0,"missing library provenance");
 auto kp=c->KeyGen();c->EvalMultKeyGen(kp.secretKey);c->EvalRotateKeyGen(kp.secretKey,indices);
 auto cp=std::dynamic_pointer_cast<CryptoParametersBGVRNS>(c->GetCryptoParameters());std::cout<<"{\"status\":\"MODULI\",\"q\":[";bool f=true;for(auto&q:cp->GetElementParams()->GetParams()){if(!f)std::cout<<',';f=false;std::cout<<q->GetModulus();}std::cout<<"],\"qp_equals_q\":true}"<<std::endl;
 const unsigned n=32768;auto ref=c->Encrypt(kp.publicKey,c->MakePackedPlaintext(V(n,0)));Packed codec(ref,nativewire(kp.publicKey));auto ones=c->MakePackedPlaintext(V(n,1));
 auto check=[&](const CT&ct,const V&want){Plaintext pt;require(c->Decrypt(kp.secretKey,ct,&pt).isValid,"decrypt refused");pt->SetLength(n);auto got=pt->GetPackedValue();unsigned bad=0;for(unsigned j=0;j<n;j++)bad+=((got[j]%65537+65537)%65537!=want[j]);std::cout<<"{\"status\":\"SLOT_CHECK\",\"level\":"<<ct->GetLevel()<<",\"mismatches\":"<<bad<<"}"<<std::endl;require(!bad,"wrong slots");};

 std::vector<V> cases;V mixed(K);for(unsigned j=0;j<K;j++)mixed[j]=j%2;
 if(task=="histogram"){mixed=V(K,0);mixed[K-1]=1;}cases.push_back(mixed);cases.push_back(V(K,0));cases.push_back(V(K,1));V invalid=mixed;invalid[0]=2;cases.push_back(invalid);invalid=mixed;invalid[K-1]=65536;invalid[K-2]=2;cases.push_back(invalid);cases={mixed,V(K,0),V(K,1),invalid};
 // Four fresh reports: mixed, zero, one, tail-invalid.
 // Fresh reports; hostile unused slots in both rows. No secret-key serialization.
 CT aggregate;V total(n,0);unsigned checks=0;size_t bytes=0;
 for(unsigned r=0;r<cases.size();r++){auto bits=cases[r];V input(n);for(unsigned j=0;j<n;j++)input[j]=(j%2?65536:1);for(unsigned j=0;j<K;j++)input[j]=bits[j];auto x=c->Encrypt(kp.publicKey,c->MakePackedPlaintext(input));bytes=report(codec.encode(x),0).size();x=codec.decode(codec.encode(x),true);
 auto z=x,d=c->EvalSub(x,ones);for(unsigned j=0;j<base;j++){z=c->EvalSquare(z);d=c->EvalSquare(d);}
 std::map<std::pair<unsigned,int>,std::pair<CT,CT>> prefix;prefix[{0,0}]={z,d};
 std::map<int,CT> aCenters;CT d0;
 for(int center:centers){auto state=prefix.at({0,0});int offset=0;unsigned used=0;
  for(int step:paths.at(center)){offset+=step;used++;auto key=std::make_pair(used,offset);if(!prefix.count(key))prefix[key]={c->EvalSquare(c->EvalRotate(state.first,step)),c->EvalSquare(c->EvalRotate(state.second,step))};state=prefix.at(key);require(state.first->GetLevel()==base+used&&state.second->GetLevel()==base+used,"rotation schedule level mismatch");}
  require(offset==center,"prefix rotation");
  for(unsigned j=base+used;j<16;j++){state.first=c->EvalSquare(state.first);state.second=c->EvalSquare(state.second);}
  require(state.first->GetLevel()==16&&state.second->GetLevel()==16,"indicator depth mismatch");auto zi=c->EvalAdd(c->EvalNegate(state.first),ones);auto di=c->EvalAdd(c->EvalNegate(state.second),ones);auto ai=c->EvalAdd(zi,di);aCenters[center]=ai;if(center==0)d0=di;
  V phi(n,0);for(unsigned j=0;j<n;j++){int row=j/16384;int pos=(int(j%16384)+center)%16384;if(pos<0)pos+=16384;auto value=input[row*16384+pos];phi[j]=value==0||value==1;}check(ai,phi);checks++;
 }
 require(bool(d0),"missing D0");d=d0;prefix.clear();
 std::map<int,CT> shifted;auto getA=[&](int offset){if(!shifted.count(offset)){int center=assigned.at(offset);int step=offset-center;require(step==0||std::find(indices.begin(),indices.end(),step)!=indices.end(),"post-power rotation budget");shifted[offset]=step?c->EvalRotate(aCenters.at(center),step):aCenters.at(center);}return shifted.at(offset);};
 bool valid=std::all_of(bits.begin(),bits.end(),[](auto v){return v==0||v==1;});if(task=="histogram")valid&=std::count(bits.begin(),bits.end(),1)==1;
 std::map<std::pair<unsigned,int>,CT> products;
 std::function<CT(unsigned,int)> getWindow=[&](unsigned r,int offset)->CT{if(!r)return getA(offset);auto key=std::make_pair(r,offset);if(!products.count(key))products[key]=c->EvalMult(getWindow(r-1,offset),getWindow(r-1,offset+(1<<(r-1))));return products.at(key);};
 CT output;
 for(unsigned k=0;k<K;k++){V mask(n,0);long weight=task=="sum"?(k==6?37:1L<<k):1;mask[k]=weight;auto selected=c->EvalMult(d,c->MakePackedPlaintext(mask));
 std::vector<CT> nodes{selected};
 auto append_range=[&](int offset,unsigned count){for(unsigned r=0;count;r++,count>>=1)if(count&1){nodes.push_back(getWindow(r,offset));offset+=1U<<r;}};
 append_range(-int(k),k);append_range(1,K-k-1);
 // Greedily combine the shallowest factors. Masked D starts one level deeper.
 while(nodes.size()>1){std::sort(nodes.begin(),nodes.end(),[](const CT&l,const CT&r){return l->GetLevel()<r->GetLevel();});auto y=c->EvalMult(nodes[0],nodes[1]);nodes.erase(nodes.begin(),nodes.begin()+2);nodes.push_back(y);}auto y=nodes[0];require(y->GetLevel()<=depth,"depth budget");V want(n,0);want[k]=valid?weight*bits[k]:0;check(y,want);checks++;auto mapped=y;output=output?c->EvalAdd(output,mapped):mapped;
 }
 V want(n,0);for(unsigned k=0;k<K;k++){long weight=task=="sum"?(k==6?37:1L<<k):1;want[k]=valid?weight*bits[k]:0;}if(task=="sum"){long scalar=std::accumulate(want.begin(),want.end(),0L);want=V(n,0);want[0]=scalar;}for(unsigned j=0;j<n;j++)total[j]+=want[j];check(output,want);check(codec.decode(codec.encode(output),false),want);checks+=2;aggregate=aggregate?c->EvalAdd(aggregate,output):output;
 std::cout<<"{\"status\":\"REPORT_PASS\",\"report\":"<<r<<",\"valid\":"<<(valid?"true":"false")<<"}"<<std::endl;
 }
 check(aggregate,total);checks++;
 // Bounded per-index serialization: do not double count cumulative key maps.
 size_t rotationbytes=0;for(auto idx:indices){std::stringstream stream;require(c->SerializeEvalAutomorphismKey(stream,SerType::BINARY,kp.secretKey->GetKeyTag(),{c->FindAutomorphismIndex(idx)}),"rotation serialize");rotationbytes+=stream.str().size();}
 std::stringstream mult;c->SerializeEvalMultKey(mult,SerType::BINARY,kp.secretKey->GetKeyTag());
 std::cout<<"{\"status\":\"EXPLORATORY_TASK_PASS\",\"task\":"<<std::quoted(task)<<",\"length\":"<<K<<",\"indicator_centers\":"<<centers.size()<<",\"rotation_stages\":"<<maxpath<<",\"reports\":"<<cases.size()<<",\"slot_checks\":"<<checks<<",\"report_bytes\":"<<bytes<<",\"rotation_key_bytes\":"<<rotationbytes<<",\"mult_key_bytes\":"<<mult.str().size()<<",\"seconds\":"<<std::chrono::duration<double>(Clock::now()-start).count()<<",\"final_task_decoding_qualified\":true,\"production_qualified\":false}"<<std::endl;
}catch(const std::exception&e){std::string s=e.what();std::replace(s.begin(),s.end(),'\n',' ');std::cout<<"{\"status\":\"FAILED\",\"reason\":"<<std::quoted(s)<<"}"<<std::endl;return 1;}}
