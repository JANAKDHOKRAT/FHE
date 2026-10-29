// Original coordinates, exact full-report contribution. No lookup encoding.
#include "native_checks.h"
#include "packed.h"
#include <chrono>
#include <fstream>
#include <numeric>
#include <queue>
#include <map>
using Clock=std::chrono::steady_clock;
int main(int argc,char**argv){try{
 require(argc==3,"usage: exact TASK LENGTH");std::string task=argv[1];unsigned K=std::stoul(argv[2]);require((task=="sum"&&K==7)||(task=="histogram"&&K==8)||(task=="sumvec"&&(K==25||K==50||K==100)),"unsupported task");
 require(task=="sumvec","vector research only");
 std::vector<int32_t> indices=K==25?std::vector<int32_t>{1,8,-8}:std::vector<int32_t>{-16,-4,-1,1,4,16};
 std::map<int,std::vector<int>> paths;std::queue<int> queue;paths[0]={};queue.push(0);
 while(!queue.empty()){int u=queue.front();queue.pop();for(int v:indices){int w=u+v;if(std::abs(w)<=int(2*K)&&!paths.count(w)){paths[w]=paths[u];paths[w].push_back(v);queue.push(w);}}}
 unsigned switches=1;for(int u=1-int(K);u<int(K);u++){auto path=paths.at(u);require(std::accumulate(path.begin(),path.end(),0)==u,"bad path");switches=std::max(switches,1U+unsigned(path.size()));}
 unsigned depth=16;for(unsigned v=K;v;v>>=1)depth++; // 16+ceil(log2(K+1)) includes one selected-D mask
 CCParams<CryptoContextBGVRNS> p;p.SetPlaintextModulus(65537);p.SetRingDim(32768);p.SetMultiplicativeDepth(depth);p.SetSecurityLevel(HEStd_128_classic);p.SetSecretKeyDist(UNIFORM_TERNARY);p.SetMultipartyMode(FIXED_NOISE_MULTIPARTY);p.SetScalingTechnique(FLEXIBLEAUTOEXT);p.SetKeySwitchTechnique(BV);p.SetDigitSize(20);p.SetEvalAddCount(task=="histogram"?0:1);p.SetKeySwitchCount(switches);
 auto start=Clock::now();auto c=GenCryptoContext(p);require(c->GetRingDimension()==32768,"ring mismatch");c->Enable(PKE);c->Enable(KEYSWITCH);c->Enable(LEVELEDSHE);c->Enable(ADVANCEDSHE);
 std::cout<<"{\"status\":\"PARAMETERS_ONLY\",\"task\":"<<std::quoted(task)<<",\"length\":"<<K<<",\"depth\":"<<depth<<",\"digit\":20,\"switches\":"<<switches<<",\"p\":65537,\"ring\":32768}"<<std::endl;
 auto kp=c->KeyGen();c->EvalMultKeyGen(kp.secretKey);c->EvalRotateKeyGen(kp.secretKey,indices);
 auto cp=std::dynamic_pointer_cast<CryptoParametersBGVRNS>(c->GetCryptoParameters());std::cout<<"{\"status\":\"MODULI\",\"q\":[";bool f=true;for(auto&q:cp->GetElementParams()->GetParams()){if(!f)std::cout<<',';f=false;std::cout<<q->GetModulus();}std::cout<<"],\"qp_equals_q\":true}"<<std::endl;
 const unsigned n=32768;auto ref=c->Encrypt(kp.publicKey,c->MakePackedPlaintext(V(n,0)));Packed codec(ref,nativewire(kp.publicKey));auto ones=c->MakePackedPlaintext(V(n,1));
 auto check=[&](const CT&ct,const V&want){Plaintext pt;require(c->Decrypt(kp.secretKey,ct,&pt).isValid,"decrypt refused");pt->SetLength(n);auto got=pt->GetPackedValue();unsigned bad=0;for(unsigned j=0;j<n;j++)bad+=((got[j]%65537+65537)%65537!=want[j]);std::cout<<"{\"status\":\"SLOT_CHECK\",\"level\":"<<ct->GetLevel()<<",\"mismatches\":"<<bad<<"}"<<std::endl;require(!bad,"wrong slots");};
 auto rotate=[&](CT ct,int offset){for(int step:paths.at(offset))ct=c->EvalRotate(ct,step);return ct;};
 std::vector<V> cases;V mixed(K);for(unsigned j=0;j<K;j++)mixed[j]=j%2;
 if(task=="histogram"){mixed=V(K,0);mixed[K-1]=1;}cases.push_back(mixed);cases.push_back(V(K,0));cases.push_back(V(K,1));V invalid=mixed;invalid[0]=2;cases.push_back(invalid);invalid=mixed;invalid[K-1]=65536;invalid[K-2]=2;cases.push_back(invalid);
 // Fresh reports; hostile unused slots in both rows. No secret-key serialization.
 CT aggregate;V total(n,0);unsigned checks=0;size_t bytes=0;
 for(unsigned r=0;r<cases.size();r++){auto bits=cases[r];V input(n);for(unsigned j=0;j<n;j++)input[j]=(j%2?65536:1);for(unsigned j=0;j<K;j++)input[j]=bits[j];auto x=c->Encrypt(kp.publicKey,c->MakePackedPlaintext(input));bytes=report(codec.encode(x),0).size();x=codec.decode(codec.encode(x),true);
 auto z=x,d=c->EvalSub(x,ones);for(unsigned j=0;j<16;j++){z=c->EvalSquare(z);d=c->EvalSquare(d);}z=c->EvalAdd(c->EvalNegate(z),ones);d=c->EvalAdd(c->EvalNegate(d),ones);auto a=task=="histogram"?z:c->EvalAdd(z,d);
 bool valid=std::all_of(bits.begin(),bits.end(),[](auto v){return v==0||v==1;});if(task=="histogram")valid&=std::count(bits.begin(),bits.end(),1)==1;
 // Dyadic window products: windows[r](s)=product_{t=0}^{2^r-1} A(s+t).
 std::vector<CT> windows{a};for(unsigned width=1;2*width<K;width*=2)windows.push_back(c->EvalMult(windows.back(),rotate(windows.back(),width)));
 CT output;
 for(unsigned k=0;k<K;k++){V mask(n,0);long weight=task=="sum"?(k==6?37:1L<<k):1;mask[k]=weight;auto selected=c->EvalMult(d,c->MakePackedPlaintext(mask));
 std::vector<CT> nodes{selected};
 auto append_range=[&](int offset,unsigned count){for(unsigned r=0;count;r++,count>>=1)if(count&1){nodes.push_back(rotate(windows[r],offset));offset+=1U<<r;}};
 append_range(-int(k),k);append_range(1,K-k-1);
 // Greedily combine the shallowest factors. Masked D starts one level deeper.
 while(nodes.size()>1){std::sort(nodes.begin(),nodes.end(),[](const CT&l,const CT&r){return l->GetLevel()<r->GetLevel();});auto y=c->EvalMult(nodes[0],nodes[1]);nodes.erase(nodes.begin(),nodes.begin()+2);nodes.push_back(y);}auto y=nodes[0];require(y->GetLevel()<=depth,"depth budget");V want(n,0);want[k]=valid?weight*bits[k]:0;check(y,want);checks++;auto mapped=task=="sum"?rotate(y,k):y;output=output?c->EvalAdd(output,mapped):mapped;
 }
 V want(n,0);for(unsigned k=0;k<K;k++){long weight=task=="sum"?(k==6?37:1L<<k):1;want[k]=valid?weight*bits[k]:0;}if(task=="sum"){long scalar=std::accumulate(want.begin(),want.end(),0L);want=V(n,0);want[0]=scalar;}for(unsigned j=0;j<n;j++)total[j]+=want[j];check(output,want);check(codec.decode(codec.encode(output),false),want);checks+=2;aggregate=aggregate?c->EvalAdd(aggregate,output):output;
 std::cout<<"{\"status\":\"REPORT_PASS\",\"report\":"<<r<<",\"valid\":"<<(valid?"true":"false")<<"}"<<std::endl;
 }
 check(aggregate,total);checks++;
 // Bounded per-index serialization: do not double count cumulative key maps.
 size_t rotationbytes=0;for(auto idx:indices){std::stringstream stream;require(c->SerializeEvalAutomorphismKey(stream,SerType::BINARY,kp.secretKey->GetKeyTag(),{c->FindAutomorphismIndex(idx)}),"rotation serialize");rotationbytes+=stream.str().size();}
 std::stringstream mult;c->SerializeEvalMultKey(mult,SerType::BINARY,kp.secretKey->GetKeyTag());
 std::cout<<"{\"status\":\"EXPLORATORY_TASK_PASS\",\"task\":"<<std::quoted(task)<<",\"length\":"<<K<<",\"reports\":"<<cases.size()<<",\"slot_checks\":"<<checks<<",\"report_bytes\":"<<bytes<<",\"rotation_key_bytes\":"<<rotationbytes<<",\"mult_key_bytes\":"<<mult.str().size()<<",\"seconds\":"<<std::chrono::duration<double>(Clock::now()-start).count()<<",\"final_task_decoding_qualified\":true,\"production_qualified\":false}"<<std::endl;
}catch(const std::exception&e){std::string s=e.what();std::replace(s.begin(),s.end(),'\n',' ');std::cout<<"{\"status\":\"FAILED\",\"reason\":"<<std::quoted(s)<<"}"<<std::endl;return 1;}}
