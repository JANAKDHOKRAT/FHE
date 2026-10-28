#include "openfhe.h"
#include <iostream>
#include <string>
using namespace lbcrypto;
int main() {
 for (auto depth : {18,20,23,24,25,26,27})
 for (auto scaling : {FLEXIBLEAUTOEXT,FLEXIBLEAUTO,FIXEDAUTO})
 for (int kind=0; kind<2; ++kind)
 for (int digit : {1,2,3,4,5,7,8,10,16,20,22,28}) {
  try {
   CCParams<CryptoContextBGVRNS> p;
   p.SetPlaintextModulus(65537); p.SetMultiplicativeDepth(depth);
   p.SetSecurityLevel(HEStd_128_classic); p.SetSecretKeyDist(UNIFORM_TERNARY);
   p.SetMultipartyMode(FIXED_NOISE_MULTIPARTY); p.SetScalingTechnique(scaling);
   if(kind==0) {p.SetKeySwitchTechnique(HYBRID);p.SetNumLargeDigits(digit);}
   else {p.SetKeySwitchTechnique(BV);p.SetDigitSize(digit);}
   auto c=GenCryptoContext(p);
   auto n=c->GetRingDimension();
   auto q=c->GetCryptoParameters()->GetElementParams();
   std::cout<<"PARAM "<<depth<<" "<<scaling<<" "<<kind<<" "<<digit<<" "<<n<<" "<<(65536%(2*n)==0)<<" "<<q->GetModulus().GetMSB()<<std::endl;
  } catch(const std::exception& e) {
   std::cout<<"REFUSED "<<depth<<" "<<scaling<<" "<<kind<<" "<<digit<<" "<<e.what()<<std::endl;
  }
 }
}
