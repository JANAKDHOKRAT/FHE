#include "openfhe.h"
#include <iostream>
#include <iomanip>
using namespace lbcrypto;
int main(){for(unsigned d:{21,22,23})for(unsigned a:{1})for(unsigned digit:{4,8,12,16,20,24}){try{CCParams<CryptoContextBGVRNS> p;p.SetPlaintextModulus(65537);p.SetRingDim(32768);p.SetMultiplicativeDepth(d);p.SetSecurityLevel(HEStd_128_classic);p.SetSecretKeyDist(UNIFORM_TERNARY);p.SetMultipartyMode(FIXED_NOISE_MULTIPARTY);p.SetScalingTechnique(FLEXIBLEAUTOEXT);p.SetKeySwitchTechnique(BV);p.SetDigitSize(digit);p.SetEvalAddCount(a);p.SetKeySwitchCount(d==21?11:d==22?15:21);auto c=GenCryptoContext(p);std::cout<<"{\"depth\":"<<d<<",\"adds\":"<<a<<",\"digit\":"<<digit<<",\"status\":\"PARAMETERS_ONLY\"}"<<std::endl;}catch(const std::exception&e){std::string s=e.what();std::replace(s.begin(),s.end(),'\n',' ');std::cout<<"{\"depth\":"<<d<<",\"adds\":"<<a<<",\"digit\":"<<digit<<",\"status\":\"REFUSED\",\"reason\":"<<std::quoted(s)<<"}"<<std::endl;}CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();}}
