// Original professor STD128/GINX binary-vector circuit, measurement adapter only.
#include "binfhecontext-ser.h"
#include <algorithm>
#include <chrono>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>
using namespace lbcrypto;using CT=LWECiphertext;using Clock=std::chrono::steady_clock;
uint64_t ns(Clock::time_point t){return std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now()-t).count();}
template<class T>std::string encode(const T&x){std::ostringstream s(std::ios::binary);Serial::Serialize(x,s,SerType::BINARY);if(!s)throw std::runtime_error("encode");return s.str();}
template<class T>T decode(const std::string&s){T x;std::istringstream f(s,std::ios::binary);Serial::Deserialize(x,f,SerType::BINARY);if(!f)throw std::runtime_error("decode");return x;}
void require(bool b,const char*s){if(!b)throw std::runtime_error(s);}
uint64_t bit(size_t i,size_t j){return (17*i+31*j+j/3+i*j/7)%2;}
void libraries(){std::ifstream f("/proc/self/maps");require(bool(f),"maps");std::string l;bool a=false,b=false;while(std::getline(f,l))if(l.find("libOPENFHE")!=std::string::npos){require(l.size()>=9&&l.substr(l.size()-9)==".so.1.4.2","library version");a|=l.find("libOPENFHEcore")!=std::string::npos;b|=l.find("libOPENFHEbinfhe")!=std::string::npos;}require(a&&b,"missing libraries");}
int main(int argc,char**argv){try{libraries();require(argc==2,"usage: boolean-cost LENGTH");size_t length=std::stoull(argv[1]);require(length==1||length==10||length==25||length==50||length==100,"workload");
 auto setup=Clock::now();BinFHEContext cc;cc.GenerateBinFHEContext(STD128,GINX);auto p=cc.GetParams()->GetLWEParams();require(p->GetN()==1024&&p->Getn()==503&&p->GetQ().ConvertToInt()==134215681&&p->Getq().ConvertToInt()==1024&&p->GetqKS().ConvertToInt()==16384&&p->GetDgg().GetStd()==3.19,"original STD128 parameters changed");
 auto t=Clock::now();auto sk=cc.KeyGen();cc.BTKeyGen(sk,PUB_ENCRYPT);auto pk=cc.GetPublicKey();auto keygen_ns=ns(t);
 t=Clock::now();auto context_bytes=encode(cc).size(),public_bytes=encode(pk).size(),switch_bytes=encode(cc.GetSwitchKey()).size(),bootstrap_bytes=encode(cc.GetRefreshKey()).size();auto secret=encode(sk);auto secret_bytes=secret.size();std::fill(secret.begin(),secret.end(),0);auto serialization_ns=ns(t);
 auto zero=cc.Encrypt(pk,0,SMALL_DIM),one=cc.Encrypt(pk,1,SMALL_DIM);auto setup_ns=ns(setup);
 std::cout<<"{\"status\":\"SETUP\",\"backend\":\"Boolean\",\"length\":"<<length<<",\"setup_ns\":"<<setup_ns<<",\"keygen_ns\":"<<keygen_ns<<",\"material_sizing_serialization_ns\":"<<serialization_ns<<",\"public_key_bytes\":"<<public_bytes<<",\"secret_key_bytes\":"<<secret_bytes<<",\"context_bytes\":"<<context_bytes<<",\"evaluation_key_bytes\":"<<switch_bytes+bootstrap_bytes<<",\"switch_key_bytes\":"<<switch_bytes<<",\"bootstrap_key_bytes\":"<<bootstrap_bytes<<",\"profile\":\"STD128/GINX\"}"<<std::endl;
 std::vector<std::vector<int>>measurements(4,std::vector<int>(length));std::vector<size_t>expected(length,0);for(size_t i=0;i<4;++i)for(size_t j=0;j<length;++j){measurements[i][j]=bit(i,j);expected[j]+=measurements[i][j];}
 uint64_t client_ns=0;std::vector<std::string>reports;std::vector<size_t>report_bytes;
 for(auto&values:measurements){t=Clock::now();std::vector<CT>report;for(auto x:values)report.push_back(cc.Encrypt(pk,x,LARGE_DIM));auto wire=encode(report);client_ns+=ns(t);report_bytes.push_back(wire.size());reports.push_back(std::move(wire));}
 size_t gates=0;auto gate=[&](BINGATE g,const CT&a,const CT&b){++gates;return cc.EvalBinGate(g,a,b);};std::vector<std::vector<CT>>sums(length);std::vector<CT>flags;uint64_t server_ns=0;
 for(size_t i=0;i<4;++i){t=Clock::now();auto report=decode<std::vector<CT>>(reports[i]);require(report.size()==length,"report shape");for(auto&x:report)x=cc.SwitchCTtoqn(cc.GetSwitchKey(),x);
  CT flag=one;std::vector<CT>bits;for(auto&x:report){auto bad=gate(AND,x,zero);auto ok=cc.EvalNOT(bad);flag=gate(AND,flag,ok);bits.push_back(gate(OR,x,zero));}for(auto&x:bits)x=gate(AND,x,flag);flags.push_back(flag);
  for(size_t j=0;j<length;++j){if(sums[j].empty()){sums[j].push_back(bits[j]);continue;}CT carry=bits[j];for(auto&d:sums[j]){auto next=gate(AND,d,carry);d=gate(XOR,d,carry);carry=next;}if(sums[j].size()<3)sums[j].push_back(carry);}
  auto elapsed=ns(t);server_ns+=elapsed;std::cout<<"{\"status\":\"REPORT_EVALUATED\",\"backend\":\"Boolean\",\"report\":"<<i<<",\"report_core_ns\":"<<elapsed<<"}"<<std::endl;
 }
 t=Clock::now();size_t ctbytes=0,coordinatebytes=0,ciphertexts=0;for(auto&v:sums){coordinatebytes+=encode(v).size();for(auto&c:v){ctbytes+=encode(c).size();++ciphertexts;}}auto output_size_diagnostic_ns=ns(t);
 // The actual bundle below is the object delivered to and decoded by collector.
 t=Clock::now();auto wire=length==1?encode(sums[0]):encode(sums);auto finalize_ns=ns(t);server_ns+=finalize_ns;
 t=Clock::now();auto decoded=length==1?std::vector<std::vector<CT>>{decode<std::vector<CT>>(wire)}:decode<std::vector<std::vector<CT>>>(wire);std::vector<size_t>actual(length,0);
 for(size_t j=0;j<length;++j)for(size_t k=0;k<decoded[j].size();++k){LWEPlaintext b;cc.Decrypt(sk,decoded[j][k],&b);require(b==0||b==1,"nonbinary output digit");actual[j]|=size_t(b)<<k;}auto collector_ns=ns(t);require(actual==expected,"aggregate mismatch");require(gates==28*length,"original gate count changed");
 t=Clock::now();for(auto&f:flags){LWEPlaintext b;cc.Decrypt(sk,f,&b);require(b==1,"valid report rejected");}auto diagnostic_ns=ns(t)+output_size_diagnostic_ns;
 std::cout<<"{\"status\":\"PASS\",\"backend\":\"Boolean\",\"task\":\""<<(length==1?"count":"sumvec")<<"\",\"length\":"<<length<<",\"batch_size\":4,\"setup_ns\":"<<setup_ns<<",\"client_total_ns\":"<<client_ns<<",\"server_total_ns\":"<<server_ns<<",\"server_finalize_ns\":"<<finalize_ns<<",\"collector_total_ns\":"<<collector_ns<<",\"diagnostic_ns\":"<<diagnostic_ns<<",\"aggregate_wire_bytes\":"<<wire.size()<<",\"aggregate_ciphertext_bytes_sum\":"<<ctbytes<<",\"aggregate_coordinate_vectors_bytes_sum\":"<<coordinatebytes<<",\"aggregate_ciphertexts\":"<<ciphertexts<<",\"evaluation_key_bytes\":"<<switch_bytes+bootstrap_bytes<<",\"public_key_bytes\":"<<public_bytes<<",\"secret_key_bytes\":"<<secret_bytes<<",\"context_bytes\":"<<context_bytes<<",\"bootstrapped_gates\":"<<gates<<",\"report_bytes\":[";
 for(size_t i=0;i<report_bytes.size();++i){if(i)std::cout<<',';std::cout<<report_bytes[i];}std::cout<<"],\"actual\":[";for(size_t i=0;i<actual.size();++i){if(i)std::cout<<',';std::cout<<actual[i];}std::cout<<"],\"expected\":[";for(size_t i=0;i<expected.size();++i){if(i)std::cout<<',';std::cout<<expected[i];}std::cout<<"],\"profile\":\"STD128/GINX\",\"scope\":\"original circuit; loaded keys; no network or deployment wrapper\"}"<<std::endl;
}catch(const std::exception&e){std::cerr<<e.what()<<std::endl;return 1;}}
