// Benchmark adapter only. Professor STD128/GINX, Count gates and incremental counter preserved.
// Original professor source/build remains untouched. Both adapters deserialize evaluator keys per batch.
#include "binfhecontext-ser.h"
#include <chrono>
#include <sstream>
#include <fstream>
#include <iostream>
#include <vector>
#include <sys/resource.h>
using namespace lbcrypto;using CT=LWECiphertext;using Clock=std::chrono::steady_clock;
uint64_t ns(Clock::time_point t){return std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now()-t).count();}
template<class T>std::string encode(const T&x){std::ostringstream s(std::ios::binary);Serial::Serialize(x,s,SerType::BINARY);if(!s)throw std::runtime_error("serialization failed");return s.str();}
template<class T>T decode(const std::string&s){T v;std::istringstream f(s,std::ios::binary);Serial::Deserialize(v,f,SerType::BINARY);if(!f)throw std::runtime_error("deserialization failed");return v;}
void check_library_versions(){
 std::ifstream maps("/proc/self/maps");if(!maps)throw std::runtime_error("cannot inspect loaded libraries");
 std::string line;bool core=false,binfhe=false;const std::string suffix=".so.1.4.2";
 while(std::getline(maps,line)){if(line.find("libOPENFHE")==std::string::npos)continue;
  if(line.size()<suffix.size()||line.compare(line.size()-suffix.size(),suffix.size(),suffix)!=0)throw std::runtime_error("wrong loaded OpenFHE version");
  core|=line.find("libOPENFHEcore")!=std::string::npos;binfhe|=line.find("libOPENFHEbinfhe")!=std::string::npos;
 }
 if(!core||!binfhe)throw std::runtime_error("required OpenFHE libraries not loaded");
}
int main(int argc,char**argv){try{check_library_versions();
 if(argc!=2)throw std::runtime_error("usage: boolean-count EPOCH");
 auto t=Clock::now();BinFHEContext cc;cc.GenerateBinFHEContext(STD128,GINX);auto sk=cc.KeyGen();cc.BTKeyGen(sk,PUB_ENCRYPT);auto setup=ns(t);auto pk=cc.GetPublicKey();
 auto p=cc.GetParams()->GetLWEParams();if(p->GetN()!=1024||p->Getn()!=503||p->GetQ().ConvertToInt()!=134215681||p->Getq().ConvertToInt()!=1024||p->GetqKS().ConvertToInt()!=16384||p->GetDgg().GetStd()!=3.19)throw std::runtime_error("original STD128 profile changed");
 t=Clock::now();auto context=encode(cc),pub=encode(pk),sw=encode(cc.GetSwitchKey()),bs=encode(cc.GetRefreshKey());auto serialize=ns(t);
 t=Clock::now();auto zero=cc.Encrypt(pk,0,SMALL_DIM);auto one=cc.Encrypt(pk,1,SMALL_DIM);auto constants=ns(t);
 cc.ClearBTKeys(); // Client/collector need parameters + pk/sk; retain serialized evaluator material, not duplicate generator keys.
 std::cout<<"{\"type\":\"setup\",\"backend\":\"Boolean\",\"profile\":\"STD128/GINX\",\"epoch\":"<<argv[1]<<",\"setup_ns\":"<<setup<<",\"key_serialize_ns\":"<<serialize<<",\"constants_ns\":"<<constants<<",\"public_key_bytes\":"<<pub.size()<<",\"context_bytes\":"<<context.size()<<",\"switch_key_bytes\":"<<sw.size()<<",\"bootstrap_key_bytes\":"<<bs.size()<<"}"<<std::endl;
 for(int run=-2;run<3;++run){const size_t n=4;bool invalid=run==-2;
  t=Clock::now();BinFHEContext server=decode<BinFHEContext>(context);RingGSWBTKey keys;keys.Pkey=decode<LWEPublicKey>(pub);keys.KSkey=decode<LWESwitchingKey>(sw);keys.BSkey=decode<RingGSWACCKey>(bs);server.BTKeyLoad(keys);auto init=ns(t);
  uint64_t client=0,deser=0,convert=0,validation=0,aggregation=0,collector=0,reportbytes=0,gates=0,expected=0,actual=0;std::vector<CT>digits,flags;std::vector<bool>valids;
  auto gate=[&](BINGATE g,const CT&a,const CT&b){++gates;return server.EvalBinGate(g,a,b);};
  for(size_t i=0;i<n;++i){int value=i%2;if(invalid&&i+2>=n)value=i+1==n?3:2;bool valid=value<2;if(value==1)++expected;
   t=Clock::now();auto wire=encode(std::vector<CT>{cc.Encrypt(pk,value,LARGE_DIM)});client+=ns(t);reportbytes=wire.size();if(reportbytes!=8245)throw std::runtime_error("Count wire size changed");
   t=Clock::now();auto report=decode<std::vector<CT>>(wire);deser+=ns(t);
   t=Clock::now();auto x=server.SwitchCTtoqn(server.GetSwitchKey(),report.at(0));convert+=ns(t);
   // Same scalar specialization of professor's four validation/masking gates.
   t=Clock::now();auto bad=gate(AND,x,zero);auto ok=server.EvalNOT(bad);auto flag=gate(AND,one,ok);auto normalized=gate(OR,x,zero);auto bit=gate(AND,normalized,flag);validation+=ns(t);flags.push_back(flag);valids.push_back(valid);
   t=Clock::now();if(digits.empty())digits.push_back(bit);else{CT carry=bit;for(auto&d:digits){auto next=gate(AND,d,carry);d=gate(XOR,d,carry);carry=next;}if(digits.size()<3)digits.push_back(carry);}aggregation+=ns(t);
  }
  t=Clock::now();auto wire=encode(digits);auto outputbytes=wire.size();aggregation+=ns(t);
  t=Clock::now();auto out=decode<std::vector<CT>>(wire);for(size_t i=0;i<out.size();++i){LWEPlaintext value;cc.Decrypt(sk,out[i],&value);if(value!=0&&value!=1)throw std::runtime_error("nonbinary count digit");actual|=size_t(value)<<i;}collector=ns(t);
  if(actual!=expected||gates!=28)throw std::runtime_error("Count/gate mismatch");
  // Diagnostic decryptions are deliberately outside measured server and collector stages.
  for(size_t i=0;i<n;++i){LWEPlaintext f;cc.Decrypt(sk,flags[i],&f);if(f!=int(valids[i]))throw std::runtime_error("flag mismatch");}
  struct rusage r;getrusage(RUSAGE_SELF,&r);
  std::cout<<"{\"type\":\"batch\",\"backend\":\"Boolean\",\"epoch\":"<<argv[1]<<",\"n\":4,\"run\":"<<run<<",\"invalid_reports\":"<<(invalid?2:0)<<",\"expected\":"<<expected<<",\"actual\":"<<actual<<",\"report_bytes\":"<<reportbytes<<",\"aggregate_bytes\":"<<outputbytes<<",\"evaluator_init_ns\":"<<init<<",\"client_ns\":"<<client<<",\"decode_ns\":"<<deser<<",\"switch_ns\":"<<convert<<",\"validate_ns\":"<<validation<<",\"aggregate_ns\":"<<aggregation<<",\"collector_ns\":"<<collector<<",\"gates\":"<<gates<<",\"peak_rss_kib\":"<<r.ru_maxrss<<",\"correct\":true}"<<std::endl;
 }
}catch(const std::exception&e){std::cerr<<e.what()<<std::endl;return 1;}}
