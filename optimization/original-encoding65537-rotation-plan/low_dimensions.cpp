// Original coordinates, exact full-report contribution. No lookup encoding.
#include "native_checks.h"
#include "packed.h"
#include <chrono>
#include <fstream>
#include <numeric>
using Clock=std::chrono::steady_clock;
int main(int argc,char**argv){try{
 require(argc==3,"usage: exact TASK LENGTH");std::string task=argv[1];unsigned K=std::stoul(argv[2]);require((task=="count"&&K==1)||(task=="sum"&&K==7)||(task=="histogram"&&(K==3||K==8))||(task=="sumvec"&&K==10),"unsupported low-dimensional task");
 unsigned depth=16;for(unsigned v=K;v;v>>=1)depth++; // 16+ceil(log2(K+1)) includes one selected-D mask
 CCParams<CryptoContextBGVRNS> p;p.SetPlaintextModulus(65537);p.SetRingDim(32768);p.SetMultiplicativeDepth(depth);p.SetSecurityLevel(HEStd_128_classic);p.SetSecretKeyDist(UNIFORM_TERNARY);p.SetMultipartyMode(FIXED_NOISE_MULTIPARTY);p.SetScalingTechnique(FLEXIBLEAUTOEXT);p.SetKeySwitchTechnique(HYBRID);p.SetNumLargeDigits(depth+2);p.SetEvalAddCount(task=="histogram"||task=="count"?0:1);unsigned switches=K;p.SetKeySwitchCount(switches);
 auto start=Clock::now();auto c=GenCryptoContext(p);require(c->GetRingDimension()==32768,"ring mismatch");c->Enable(PKE);c->Enable(KEYSWITCH);c->Enable(LEVELEDSHE);c->Enable(ADVANCEDSHE);
 std::cout<<"{\"status\":\"PARAMETERS_ONLY\",\"task\":"<<std::quoted(task)<<",\"length\":"<<K<<",\"depth\":"<<depth<<",\"key_switch\":\"HYBRID\",\"digits\":"<<(depth+2)<<",\"p\":65537,\"ring\":32768}"<<std::endl;
 auto kp=c->KeyGen();c->EvalMultKeyGen(kp.secretKey);std::vector<int32_t> indices;if(K>1){indices={-1,1};c->EvalRotateKeyGen(kp.secretKey,indices);}
 auto cp=std::dynamic_pointer_cast<CryptoParametersBGVRNS>(c->GetCryptoParameters());std::cout<<"{\"status\":\"MODULI\",\"q\":[";bool f=true;for(auto&q:cp->GetElementParams()->GetParams()){if(!f)std::cout<<',';f=false;std::cout<<q->GetModulus();}std::cout<<"],\"qp\":[";f=true;for(auto&q:cp->GetParamsQP()->GetParams()){if(!f)std::cout<<',';f=false;std::cout<<q->GetModulus();}std::cout<<"]}"<<std::endl;
 const unsigned n=32768;auto ref=c->Encrypt(kp.publicKey,c->MakePackedPlaintext(V(n,0)));Packed codec(ref,nativewire(kp.publicKey));auto ones=c->MakePackedPlaintext(V(n,1));
 auto check=[&](const CT&ct,const V&want){Plaintext pt;require(c->Decrypt(kp.secretKey,ct,&pt).isValid,"decrypt refused");pt->SetLength(n);auto got=pt->GetPackedValue();unsigned bad=0;for(unsigned j=0;j<n;j++)bad+=((got[j]%65537+65537)%65537!=want[j]);std::cout<<"{\"status\":\"SLOT_CHECK\",\"level\":"<<ct->GetLevel()<<",\"mismatches\":"<<bad<<"}"<<std::endl;require(!bad,"wrong slots");};
 auto rotate=[&](CT ct,int offset){for(int j=0;j<std::abs(offset);j++)ct=c->EvalRotate(ct,offset<0?-1:1);return ct;};
 std::vector<V> cases;V mixed(K);for(unsigned j=0;j<K;j++)mixed[j]=j%2;
 if(task=="histogram"){mixed=V(K,0);mixed[K-1]=1;}cases.push_back(mixed);cases.push_back(V(K,0));cases.push_back(V(K,1));V invalid=mixed;invalid[0]=2;cases.push_back(invalid);invalid=mixed;if(K>1){invalid[K-1]=65536;invalid[K-2]=2;}else invalid[0]=3;cases.push_back(invalid);if(task=="count")cases={{0},{1},{2},{65536},{3}};
 // Fresh reports; hostile unused slots in both rows. No secret-key serialization.
 CT aggregate;V total(n,0);unsigned checks=0;size_t bytes=0;
 for(unsigned r=0;r<cases.size();r++){auto bits=cases[r];V input(n);for(unsigned j=0;j<n;j++)input[j]=(j%2?65536:1);for(unsigned j=0;j<K;j++)input[j]=bits[j];auto x=c->Encrypt(kp.publicKey,c->MakePackedPlaintext(input));bytes=report(codec.encode(x),0).size();x=codec.decode(codec.encode(x),true);
 auto z=x,d=c->EvalSub(x,ones);for(unsigned j=0;j<16;j++){if(task!="count")z=c->EvalSquare(z);d=c->EvalSquare(d);}CT a;if(task!="count"){z=c->EvalAdd(c->EvalNegate(z),ones);}d=c->EvalAdd(c->EvalNegate(d),ones);if(task!="count")a=task=="histogram"?z:c->EvalAdd(z,d);
 bool valid=std::all_of(bits.begin(),bits.end(),[](auto v){return v==0||v==1;});if(task=="histogram")valid&=std::count(bits.begin(),bits.end(),1)==1;
 CT output;
 for(unsigned k=0;k<K;k++){V mask(n,0);long weight=task=="sum"?(k==6?37:1L<<k):1;mask[k]=weight;auto selected=c->EvalMult(d,c->MakePackedPlaintext(mask));
 std::vector<CT> nodes{selected};for(unsigned j=0;j<K;j++)if(j!=k)nodes.push_back(rotate(a,int(j)-int(k)));
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
