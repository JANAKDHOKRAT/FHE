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
#include <filesystem>
using Clock=std::chrono::steady_clock;
int main(int argc,char**argv){try{
 require(argc==3,"usage: exact TASK LENGTH");std::string task=argv[1];unsigned K=std::stoul(argv[2]);require((task=="sum"&&K==7)||(task=="histogram"&&K==8)||(task=="sumvec"&&(K==25||K==50||K==100)),"unsupported task");
 require(task=="sumvec"&&K==100,"isolated 100-bit research only");
 std::vector<int32_t> indices={1,8,-11};
 std::map<int,std::vector<int>> paths;std::queue<int> queue;paths[0]={};queue.push(0);
 while(!queue.empty()){int u=queue.front();queue.pop();for(int v:indices){int w=u+v;if(std::abs(w)<=int(2*K)&&!paths.count(w)){paths[w]=paths[u];paths[w].push_back(v);queue.push(w);}}}
 std::vector<int> centers={0,66,-67,-63,70};
 std::map<int,unsigned> postDepth;std::map<int,std::pair<int,int>> parent;std::queue<int> postQueue;
 for(int center:centers){postDepth[center]=0;postQueue.push(center);}
 while(!postQueue.empty()){int u=postQueue.front();postQueue.pop();if(postDepth[u]==6)continue;for(int step:indices){int v=u+step;if(std::abs(v)<=int(2*K)&&!postDepth.count(v)){postDepth[v]=postDepth[u]+1;parent[v]={u,step};postQueue.push(v);}}}
 for(int u=1-int(K);u<int(K);u++)require(postDepth.count(u)&&postDepth.at(u)<=6,"post-rotation coverage");
 unsigned maxpath=0;for(int center:centers){maxpath=std::max(maxpath,unsigned(paths.at(center).size()));require(paths.at(center).size()<=97,"pre-rotation budget");}unsigned switches=7;
 unsigned depth=16;for(unsigned v=K;v;v>>=1)depth++; // 16+ceil(log2(K+1)) includes one selected-D mask
 CCParams<CryptoContextBGVRNS> p;p.SetPlaintextModulus(65537);p.SetRingDim(32768);p.SetMultiplicativeDepth(depth);p.SetSecurityLevel(HEStd_128_classic);p.SetSecretKeyDist(UNIFORM_TERNARY);p.SetMultipartyMode(FIXED_NOISE_MULTIPARTY);p.SetScalingTechnique(FLEXIBLEAUTOEXT);p.SetKeySwitchTechnique(BV);p.SetDigitSize(8);p.SetEvalAddCount(task=="histogram"?0:1);p.SetKeySwitchCount(switches);
 auto start=Clock::now();auto c=GenCryptoContext(p);require(c->GetRingDimension()==32768,"ring mismatch");c->Enable(PKE);c->Enable(KEYSWITCH);c->Enable(LEVELEDSHE);c->Enable(ADVANCEDSHE);
 std::cout<<"{\"status\":\"PARAMETERS_ONLY\",\"task\":"<<std::quoted(task)<<",\"length\":"<<K<<",\"depth\":"<<depth<<",\"digit\":8,\"switches\":"<<switches<<",\"p\":65537,\"ring\":32768}"<<std::endl;
 std::ifstream libraries("/proc/self/maps");std::string loaded;unsigned seen=0;while(std::getline(libraries,loaded))if(loaded.find("libOPENFHE")!=std::string::npos){require(loaded.find("/workspace/fhe-deps/install-bound-prime-study/lib/")!=std::string::npos,"mixed SDK");seen++;}require(seen>0,"missing library provenance");
 auto kp=c->KeyGen();c->EvalMultKeyGen(kp.secretKey);c->EvalRotateKeyGen(kp.secretKey,indices);
 // Bounded per-index serialization: do not double count cumulative key maps.
 size_t rotationbytes=0;for(auto idx:indices){std::stringstream stream;require(c->SerializeEvalAutomorphismKey(stream,SerType::BINARY,kp.secretKey->GetKeyTag(),{c->FindAutomorphismIndex(idx)}),"rotation serialize");rotationbytes+=stream.str().size();}
 size_t multbytes;{std::stringstream mult;require(c->SerializeEvalMultKey(mult,SerType::BINARY,kp.secretKey->GetKeyTag()),"mult serialize");multbytes=mult.str().size();}
 std::cout<<"{\"status\":\"KEY_BUDGET\",\"rotation_key_bytes\":"<<rotationbytes<<",\"mult_key_bytes\":"<<multbytes<<",\"reference_limit\":7429158368}"<<std::endl;
 require(rotationbytes+multbytes<=7429158368ULL,"key budget exceeded");

 auto cp=std::dynamic_pointer_cast<CryptoParametersBGVRNS>(c->GetCryptoParameters());std::cout<<"{\"status\":\"MODULI\",\"q\":[";bool f=true;for(auto&q:cp->GetElementParams()->GetParams()){if(!f)std::cout<<',';f=false;std::cout<<q->GetModulus();}std::cout<<"],\"qp_equals_q\":true}"<<std::endl;
 const unsigned n=32768;auto ref=c->Encrypt(kp.publicKey,c->MakePackedPlaintext(V(n,0)));auto publicBytes=nativewire(kp.publicKey);Packed codec(ref,publicBytes);auto ones=c->MakePackedPlaintext(V(n,1));
 auto check=[&](const CT&ct,const V&want){Plaintext pt;require(c->Decrypt(kp.secretKey,ct,&pt).isValid,"decrypt refused");pt->SetLength(n);auto got=pt->GetPackedValue();unsigned bad=0;for(unsigned j=0;j<n;j++)bad+=((got[j]%65537+65537)%65537!=want[j]);std::cout<<"{\"status\":\"SLOT_CHECK\",\"level\":"<<ct->GetLevel()<<",\"mismatches\":"<<bad<<"}"<<std::endl;require(!bad,"wrong slots");};

 const char* fixture=std::getenv("FHE_PUBLIC_FIXTURE_DIR");
 if(fixture){require(!std::filesystem::exists(fixture),"refuse existing fixture directory");std::filesystem::create_directories(fixture);}
 auto savePublic=[&](const std::string&name,const Bytes&data){if(fixture){std::ofstream out(std::filesystem::path(fixture)/name,std::ios::binary);require(bool(out),"fixture open");out.write(reinterpret_cast<const char*>(data.data()),data.size());require(bool(out),"fixture write");}};
 savePublic("public_key.bin",publicBytes);
 std::vector<V> cases;V mixed(K);for(unsigned j=0;j<K;j++)mixed[j]=j%2;
 if(task=="histogram"){mixed=V(K,0);mixed[K-1]=1;}cases.push_back(mixed);cases.push_back(V(K,0));cases.push_back(V(K,1));V invalid=mixed;invalid[0]=2;cases.push_back(invalid);invalid=mixed;invalid[K-1]=65536;invalid[K-2]=2;cases.push_back(invalid);cases={mixed,V(K,0),V(K,1),invalid};
 // Four fresh reports: mixed, zero, one, tail-invalid.
 // Fresh reports; hostile unused slots in both rows. No secret-key serialization.
 CT aggregate;V total(n,0);unsigned checks=0;size_t bytes=0;
 for(unsigned r=0;r<cases.size();r++){auto bits=cases[r];V input(n);for(unsigned j=0;j<n;j++)input[j]=(j%2?65536:1);for(unsigned j=0;j<K;j++)input[j]=bits[j];auto x=c->Encrypt(kp.publicKey,c->MakePackedPlaintext(input));auto clientWire=report(codec.encode(x),0);bytes=clientWire.size();if(r==0)savePublic("report.bin",clientWire);x=codec.decode(codec.encode(x),true);
 unsigned rotationStages=(maxpath+5)/6;require(rotationStages<=16,"late rotation capacity");unsigned sharedDepth=16-rotationStages;
 auto commonZ=x,commonD=c->EvalSub(x,ones);for(unsigned stage=0;stage<sharedDepth;stage++){commonZ=c->EvalSquare(commonZ);commonD=c->EvalSquare(commonD);}
 require(commonZ->GetLevel()==sharedDepth&&commonD->GetLevel()==sharedDepth,"shared power depth");
 std::map<int,CT> aCenters;CT d;
 for(int center:centers){auto zc=commonZ,dc=commonD;auto moves=paths.at(center);size_t used=0;
  for(unsigned stage=sharedDepth;stage<16;stage++){unsigned count=0,limit=6;while(used<moves.size()&&count<limit){int step=moves[used++];zc=c->EvalRotate(zc,step);dc=c->EvalRotate(dc,step);count++;}zc=c->EvalSquare(zc);dc=c->EvalSquare(dc);require(zc->GetLevel()==stage+1&&dc->GetLevel()==stage+1,"pre-power depth");}
  require(used==moves.size(),"unfinished pre-rotation");auto zi=c->EvalAdd(c->EvalNegate(zc),ones);auto di=c->EvalAdd(c->EvalNegate(dc),ones);auto ai=c->EvalAdd(zi,di);aCenters[center]=ai;if(center==0)d=di;
  V phi(n,0);for(unsigned j=0;j<n;j++){int row=j/16384;int pos=(int(j%16384)+center)%16384;if(pos<0)pos+=16384;auto value=input[row*16384+pos];phi[j]=value==0||value==1;}check(ai,phi);checks++;
 }
 require(bool(d),"missing D0");std::map<int,CT> shifted=aCenters;
 std::function<CT(int)> getA=[&](int offset)->CT{if(!shifted.count(offset)){auto edge=parent.at(offset);require(postDepth.at(offset)<=6,"post-rotation depth");shifted[offset]=c->EvalRotate(getA(edge.first),edge.second);}return shifted.at(offset);};
 bool valid=std::all_of(bits.begin(),bits.end(),[](auto v){return v==0||v==1;});if(task=="histogram")valid&=std::count(bits.begin(),bits.end(),1)==1;
 std::map<std::pair<unsigned,int>,CT> canonical,products;
 std::function<CT(unsigned,int)> getCanonical=[&](unsigned level,int center)->CT{if(!level)return aCenters.at(center);auto key=std::make_pair(level,center);if(!canonical.count(key)){auto source=getCanonical(level-1,center);int delta=1<<(level-1);auto steps=paths.at(delta);require(steps.size()<=6,"canonical rotation budget");auto moved=source;for(int step:steps)moved=c->EvalRotate(moved,step);auto value=c->EvalMult(source,moved);require(value->GetLevel()==16+level,"canonical window depth");canonical[key]=value;}return canonical.at(key);};
 std::function<CT(unsigned,int)> getWindow=[&](unsigned level,int offset)->CT{if(!level)return getA(offset);if(aCenters.count(offset))return getCanonical(level,offset);auto key=std::make_pair(level,offset);if(!products.count(key)){auto edge=parent.at(offset);require(postDepth.at(offset)<=6,"window post-rotation budget");products[key]=c->EvalRotate(getWindow(level,edge.first),edge.second);}return products.at(key);};
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
 check(aggregate,total);checks++;auto packedAggregate=codec.encode(aggregate);auto collectorWire=bundle(packedAggregate);check(codec.decode(readbundle(collectorWire),false),total);checks++;savePublic("aggregate.bin",collectorWire);
 std::cout<<"{\"status\":\"EXPLORATORY_TASK_PASS\",\"task\":"<<std::quoted(task)<<",\"length\":"<<K<<",\"indicator_centers\":"<<centers.size()<<",\"maximum_pre_rotation_steps\":"<<maxpath<<",\"reports\":"<<cases.size()<<",\"slot_checks\":"<<checks<<",\"report_bytes\":"<<bytes<<",\"aggregate_wire_bytes\":"<<collectorWire.size()<<",\"aggregate_ciphertext_bytes_sum\":"<<packedAggregate.size()<<",\"aggregate_ciphertexts\":1,\"rotation_key_bytes\":"<<rotationbytes<<",\"mult_key_bytes\":"<<multbytes<<",\"seconds\":"<<std::chrono::duration<double>(Clock::now()-start).count()<<",\"final_task_decoding_qualified\":true,\"production_qualified\":false}"<<std::endl;
}catch(const std::exception&e){std::string s=e.what();std::replace(s.begin(),s.end(),'\n',' ');std::cout<<"{\"status\":\"FAILED\",\"reason\":"<<std::quoted(s)<<"}"<<std::endl;return 1;}}
