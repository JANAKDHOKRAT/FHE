// Isolated research circuit. No deployment, authentication, or malicious-ciphertext claim.
#include "openfhe.h"
#include "cryptocontext-ser.h"
#include "ciphertext-ser.h"
#include <algorithm>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <vector>
using namespace lbcrypto;
using CT=Ciphertext<DCRTPoly>;
using V=std::vector<int64_t>;
void require(bool b,const std::string& s) {if(!b)throw std::runtime_error(s);}
std::string wire(const CT& c) {std::ostringstream s(std::ios::binary);Serial::Serialize(c,s,SerType::BINARY);return s.str();}
CT read(const std::string& s) {CT c;std::istringstream in(s,std::ios::binary);Serial::Deserialize(c,in,SerType::BINARY);return c;}
int main() {try {
 CCParams<CryptoContextBGVRNS> params;
 params.SetPlaintextModulus(65537);params.SetMultiplicativeDepth(21);
 params.SetSecurityLevel(HEStd_128_classic);params.SetSecretKeyDist(UNIFORM_TERNARY);
 params.SetMultipartyMode(FIXED_NOISE_MULTIPARTY);
 params.SetScalingTechnique(FLEXIBLEAUTOEXT);params.SetKeySwitchTechnique(BV);params.SetDigitSize(22);
 auto c=GenCryptoContext(params);
 c->Enable(PKE);c->Enable(KEYSWITCH);c->Enable(LEVELEDSHE);c->Enable(ADVANCEDSHE);
 const size_t n=c->GetRingDimension(),row=n/2;
 require(n==32768 && 65536%(2*n)==0,"small-ring requirement failed");
 auto kp=c->KeyGen();c->EvalMultKeyGen(kp.secretKey);
 std::vector<int32_t> indices={1,2,4,8};
 for(int d=8;d<(int)row;d*=2)indices.push_back(-d);
 c->EvalRotateKeyGen(kp.secretKey,indices);
 std::cout<<"PROFILE p=65537 ring="<<n<<" depth=21 security=HEStd_128_classic key_switch=BV digit_size=22 log2Qceil="<<c->GetCryptoParameters()->GetElementParams()->GetModulus().GetMSB()<<std::endl;
 auto pt=[&](const V& v){return c->MakePackedPlaintext(v);};
 auto one=pt(V(n,1)),two=pt(V(n,2));
 auto power=[&](CT x){for(int j=0;j<16;++j)x=c->EvalSquare(x);return x;};
 auto bit=[](int64_t x){return x==0 || x==1;};
 size_t total=0;
 for(auto kind:{std::string("sumvec10"),std::string("histogram3"),std::string("histogram8"),std::string("sum127")}) {
  const bool histogram=kind.find("histogram")==0,sum=kind=="sum127";
  const size_t length=sum?7:(kind=="sumvec10"?10:(kind=="histogram3"?3:8));
  size_t block=1;while(block<length)block*=2;
  V mask(n,0);std::fill(mask.begin(),mask.begin()+length,1);auto select=pt(mask);
  V weights(n,0);if(sum)for(size_t j=0;j<row;++j)if(j%block<length)weights[j]=int64_t(1)<<(j%block);
  auto weight=pt(weights);
  // Valid, invalid, cancelling-residual, and first/last-coordinate cases.
  std::vector<V> reports;
  V zero(length,0),ones(length,1),alternating(length,0);for(size_t j=0;j<length;++j)alternating[j]=j%2;
  if(histogram) {V first=zero,last=zero;first[0]=1;last[length-1]=1;reports={first,last,zero,ones};}
  else reports={zero,ones,alternating};
  V bad=ones;bad[0]=2;reports.push_back(bad);bad=ones;bad[length-1]=65536;reports.push_back(bad);
  // 2/5 and -1/5 have opposite bitness residuals; both are invalid.
  int64_t inv5=1;while(inv5*5%65537!=1)++inv5;
  bad=zero;bad[0]=2*inv5%65537;bad[length-1]=65537-inv5;reports.push_back(bad);
  CT aggregate;V expected(length,0);int64_t expectedSum=0;
  size_t bytes=0;
  for(size_t report=0;report<reports.size();++report) {
   const auto& values=reports[report];
   const bool valid=std::all_of(values.begin(),values.end(),bit) && (!histogram || std::count(values.begin(),values.end(),1)==1);
   if(valid)for(size_t j=0;j<length;++j){expected[j]+=values[j];if(sum)expectedSum+=values[j]*(int64_t(1)<<j);}
   // Deliberately hostile unused slots and second row. The evaluator masks them.
   V slots(n,65536);std::copy(values.begin(),values.end(),slots.begin());
   auto encrypted=c->Encrypt(kp.publicKey,pt(slots));auto encoded=wire(encrypted);
   if(!bytes)bytes=encoded.size();require(bytes==encoded.size(),"variable fresh report size");
   CT x=c->EvalMult(read(encoded),select);
   // Authorized block only, replicated periodically within the first row.
   for(size_t d=block;d<row;d*=2)x=c->EvalAdd(x,c->EvalRotate(x,-(int)d));
   auto u=power(c->EvalSub(x,one));
   auto r=c->EvalSub(one,u); // R(x) = [x=1]
   auto b=c->EvalSub(c->EvalSub(two,power(x)),u); // B(x) = [x in {0,1}]
   for(size_t d=1;d<block;d*=2) {
    auto other=c->EvalRotate(b,(int)d);
    r=c->EvalMult(r,other);
    b=c->EvalMult(b,other);
   }
   if(histogram) {
    auto s=x;for(size_t d=1;d<block;d*=2)s=c->EvalAdd(s,c->EvalRotate(s,(int)d));
    auto validTotal=c->EvalSub(one,power(c->EvalSub(s,one)));
    r=c->EvalMult(r,validTotal);
   }
   if(sum) {
    r=c->EvalMult(r,weight);
    for(size_t d=1;d<block;d*=2)r=c->EvalAdd(r,c->EvalRotate(r,(int)d));
   }
   require(r->GetLevel()<=21,"circuit exceeded declared depth");
   // Check each report, including all first-row repetitions and all second-row slots.
   Plaintext decoded;c->Decrypt(kp.secretKey,read(wire(r)),&decoded);decoded->SetLength(n);
   auto got=decoded->GetPackedValue();
   for(size_t j=0;j<n;++j) {
    int64_t want=0;
    if(valid && j<row) {
     if(sum)for(size_t k=0;k<length;++k)want+=values[k]*(int64_t(1)<<k);
     else if(j%block<length)want=values[j%block];
    }
    auto v=(got[j]%65537+65537)%65537;
    require(v==want,"per-report output/slot isolation failure: "+kind+" report="+std::to_string(report)+" slot="+std::to_string(j)+" got="+std::to_string(v)+" expected="+std::to_string(want));
   }
   aggregate=aggregate?c->EvalAdd(aggregate,r):r;
   ++total;
   std::cout<<"REPORT_PASS task="<<kind<<" i="<<report<<" valid="<<valid<<" level="<<r->GetLevel()<<" bytes_native="<<bytes<<std::endl;
  }
  Plaintext decoded;c->Decrypt(kp.secretKey,read(wire(aggregate)),&decoded);decoded->SetLength(n);auto got=decoded->GetPackedValue();
  for(size_t j=0;j<n;++j) {
   int64_t want=j>=row?0:(sum?expectedSum:(j%block<length?expected[j%block]:0));
   require((got[j]%65537+65537)%65537==want,"aggregate failure: "+kind);
  }
  std::cout<<"TASK_PASS "<<kind<<" reports="<<reports.size()<<" native_report_bytes="<<bytes<<std::endl;
 }
 std::cout<<"ALL_PASS reports="<<total<<std::endl;
}catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<std::endl;return 1;}}
