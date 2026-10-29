#pragma once
#include "openfhe.h"
#include <iostream>
#include <iomanip>
#include <stdexcept>
#include <functional>
using namespace lbcrypto;
using CT=Ciphertext<DCRTPoly>;using V=std::vector<int64_t>;
void require(bool b,const std::string&s){if(!b)throw std::runtime_error(s);}
CT rebuild(const CT& c){auto out=c->Clone();std::vector<DCRTPoly> polys;
 for(const auto &source:c->GetElements()){
  require(source.GetFormat()==Format::EVALUATION,"non-evaluation source");
  auto params=source.GetParams();DCRTPoly back(params,Format::EVALUATION,true);
  for(size_t t=0;t<source.GetNumOfElements();t++){
   auto tower=back.GetElementAtIndex(t);const auto &original=source.GetElementAtIndex(t);NativeVector values(source.GetRingDimension(),tower.GetModulus());
   std::vector<uint64_t> exported;for(size_t i=0;i<source.GetRingDimension();i++)exported.push_back(original.GetValues()[i].ConvertToInt<uint64_t>());
   for(size_t i=0;i<exported.size();i++){require(exported[i]<tower.GetModulus().ConvertToInt<uint64_t>(),"invalid residue");values[i]=NativeInteger(exported[i]);}
   tower.SetValues(std::move(values),Format::EVALUATION);back.SetElementAtIndex(t,std::move(tower));
  }require(back==source,"residue rebuild differs");polys.push_back(std::move(back));
 }out->SetElements(std::move(polys));return out;
}
inline size_t qualify(CryptoContext<DCRTPoly> c,const KeyPair<DCRTPoly>& kp,unsigned depth,const std::function<CT(const CT&)>& wirecheck){
 V a(32768),b(32768);for(size_t i=0;i<a.size();i++){a[i]=i%5==0?0:i%5==1?1:i%5==2?65536:i%65537;b[i]=(3*i+5)%65537;}
 auto ca=c->Encrypt(kp.publicKey,c->MakePackedPlaintext(a)),cb=c->Encrypt(kp.publicKey,c->MakePackedPlaintext(b));size_t checks=0;
 auto check=[&](const CT&ct,const V&want){auto back=rebuild(ct);auto encoded=wirecheck(back);require(encoded->GetElements()==back->GetElements(),"packed coefficients differ");back=encoded;require(back->GetLevel()==ct->GetLevel()&&back->GetNoiseScaleDeg()==ct->GetNoiseScaleDeg()&&back->GetScalingFactorInt()==ct->GetScalingFactorInt(),"metadata changed");
 for(const auto& x:{ct,back}){Plaintext out;auto r=c->Decrypt(kp.secretKey,x,&out);require(r.isValid,"decrypt invalid");out->SetLength(32768);auto got=out->GetPackedValue();require(got.size()==want.size(),"slot length");for(size_t i=0;i<got.size();i++)require((got[i]%65537+65537)%65537==want[i],"decryption mismatch at level "+std::to_string(ct->GetLevel())+" slot "+std::to_string(i));}checks++;return back;};
 check(ca,a);check(cb,b);V want=a;for(size_t i=0;i<a.size();i++)want[i]=(a[i]+b[i])%65537;check(c->EvalAdd(ca,cb),want);
 for(size_t i=0;i<a.size();i++)want[i]=a[i]*b[i]%65537;check(c->EvalMult(ca,cb),want);check(c->EvalMult(ca,c->MakePackedPlaintext(b)),want);
 auto x=ca;want=a;
 for(unsigned level=1;level<=depth;level++){
  x=c->EvalSquare(x);for(auto&v:want)v=v*v%65537;x=check(x,want);require(x->GetLevel()==level,"level accounting mismatch");
  V rotated=want;for(size_t i=0;i<want.size();i++)rotated[i]=want[i/16384*16384+(i%16384+1)%16384];check(c->EvalRotate(x,1),rotated);
  
 }
return checks;
}
