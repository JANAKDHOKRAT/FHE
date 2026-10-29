#pragma once
#include "cryptocontext-ser.h"
#include "ciphertext-ser.h"
#include "key/key-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"
#include <openssl/sha.h>
#include <array>
#include <cstring>
using Bytes=std::vector<uint8_t>;
using Hash=std::array<uint8_t,32>;
Hash digest(const Bytes&v){Hash h;SHA256(v.data(),v.size(),h.data());return h;}
void put(Bytes&v,uint64_t x,unsigned bytes){for(unsigned i=0;i<bytes;i++)v.push_back((x>>(8*i))&255);}
uint64_t get(const Bytes&v,size_t i,unsigned bytes){require(i+bytes<=v.size(),"short header");uint64_t x=0;for(unsigned j=0;j<bytes;j++)x|=uint64_t(v[i+j])<<(8*j);return x;}
void varint(Bytes&v,uint64_t x){do{uint8_t b=x&127;x>>=7;v.push_back(b|(x?128:0));}while(x);}
uint64_t readvar(const Bytes&v,size_t&at){uint64_t x=0;for(unsigned shift=0;shift<64;shift+=7){require(at<v.size(),"short varint");auto b=v[at++];require(shift<63||(b&127)<=1,"varint overflow");x|=uint64_t(b&127)<<shift;if(!(b&128)){require(shift==0||(b&127)!=0,"noncanonical varint");return x;}}throw std::runtime_error("varint overflow");}
template<class T>Bytes nativewire(const T&x){std::ostringstream s(std::ios::binary);Serial::Serialize(x,s,SerType::BINARY);require(bool(s),"native serialization failed");auto b=s.str();return Bytes(b.begin(),b.end());}
struct Packed{
 CT ref;std::vector<uint64_t>q;Hash fp;
 Packed(CT r,const Bytes&pk):ref(r){for(auto&t:r->GetElements()[0].GetParams()->GetParams())q.push_back(t->GetModulus().ConvertToInt<uint64_t>());
 Bytes domain;std::string name="fhe-prio3/1 packed-ciphertext";put(domain,name.size(),4);domain.insert(domain.end(),name.begin(),name.end());put(domain,65537,8);put(domain,32768,4);put(domain,q.size(),4);for(auto x:q)put(domain,x,8);auto h=digest(pk);domain.insert(domain.end(),h.begin(),h.end());fp=digest(domain);
 }
 Bytes encode(const CT&c){auto&e=c->GetElements();require(e.size()==2,"only two-element ciphertexts");size_t k=e[0].GetNumOfElements();require(c->GetLevel()+k==q.size(),"tower/level mismatch");Bytes b={'F','P','C','1',1,2};put(b,k,2);put(b,c->GetLevel(),4);b.push_back(c->GetNoiseScaleDeg());put(b,0,3);put(b,c->GetScalingFactorInt().ConvertToInt<uint64_t>(),8);b.insert(b.end(),fp.begin(),fp.end());
 unsigned __int128 acc=0;unsigned count=0;
 for(auto &poly:e){require(poly.GetFormat()==Format::EVALUATION,"bad format");for(size_t t=0;t<k;t++){require(poly.GetElementAtIndex(t).GetModulus().ConvertToInt<uint64_t>()==q[t],"bad tower");unsigned w=64-__builtin_clzll(q[t]-1);for(size_t i=0;i<32768;i++){auto x=poly.GetElementAtIndex(t).GetValues()[i].ConvertToInt<uint64_t>();require(x<q[t],"bad residue");acc|=(unsigned __int128)x<<count;count+=w;while(count>=8){b.push_back(uint8_t(acc));acc>>=8;count-=8;}}}}
 if(count)b.push_back(uint8_t(acc));return b;
 }
 CT decode(const Bytes&b,bool fresh){require(b.size()>=56,"short ciphertext");require(std::memcmp(b.data(),"FPC1",4)==0&&b[4]==1&&b[5]==2,"bad header");size_t k=get(b,6,2),level=get(b,8,4);auto degree=b[12];uint64_t scale=get(b,16,8);
 require(k>0&&k<=q.size()&&level+k==q.size(),"bad shape");require(degree==1||degree==2,"bad noise degree");require(get(b,13,3)==0&&scale>0&&scale<65537,"bad metadata");require(std::equal(fp.begin(),fp.end(),b.begin()+24),"bad fingerprint");
 if(fresh)require(k==q.size()&&level==0&&degree==ref->GetNoiseScaleDeg()&&scale==ref->GetScalingFactorInt().ConvertToInt<uint64_t>(),"nonfresh report");
 size_t widths=0;for(size_t t=0;t<k;t++)widths+=64-__builtin_clzll(q[t]-1);require(b.size()==56+(2*32768*widths+7)/8,"bad length");
 unsigned __int128 acc=0;unsigned count=0;size_t at=56;std::vector<DCRTPoly> elems;
 for(unsigned e=0;e<2;e++){DCRTPoly x=ref->GetElements()[e];if(k<q.size())x.DropLastElements(q.size()-k);
 for(size_t t=0;t<k;t++){auto tw=x.GetElementAtIndex(t);NativeVector v(32768,tw.GetModulus());unsigned w=64-__builtin_clzll(q[t]-1);for(size_t i=0;i<32768;i++){while(count<w){require(at<b.size(),"short payload");acc|=(unsigned __int128)b[at++]<<count;count+=8;}uint64_t value=uint64_t(acc&(((unsigned __int128)1<<w)-1));acc>>=w;count-=w;require(value<q[t],"residue out of range");v[i]=NativeInteger(value);}tw.SetValues(std::move(v),Format::EVALUATION);x.SetElementAtIndex(t,std::move(tw));}elems.push_back(std::move(x));}
 require(acc==0&&at==b.size(),"nonzero padding");auto c=ref->Clone();c->SetElements(std::move(elems));c->SetLevel(level);c->SetNoiseScaleDeg(degree);c->SetScalingFactorInt(NativeInteger(scale));return c;
 }
};
Hash reportid(const Bytes&c,unsigned group){std::string name="fhe-prio3/2 report";Bytes b(name.begin(),name.end());b.insert(b.end(),32,0xE9);put(b,group,4);put(b,1,4);put(b,c.size(),8);b.insert(b.end(),c.begin(),c.end());return digest(b);}
Bytes report(const Bytes&c,unsigned group){Bytes b(32,0xE9);auto h=reportid(c,group);b.insert(b.end(),h.begin(),h.end());varint(b,group);varint(b,1);varint(b,c.size());b.insert(b.end(),c.begin(),c.end());b.push_back(0);return b;}
Bytes readreport(const Bytes&b,unsigned expected_group){require(b.size()>=71,"short report");require(std::all_of(b.begin(),b.begin()+32,[](auto x){return x==0xE9;}),"task mismatch");size_t at=64;auto group=readvar(b,at);require(group==expected_group&&group<2,"group mismatch");require(readvar(b,at)==1,"chunk count");auto length=readvar(b,at);require(length<=b.size()-at&&at+length+1==b.size()&&b.back()==0,"report shape");Bytes c(b.begin()+at,b.begin()+at+length);auto h=reportid(c,group);require(std::equal(h.begin(),h.end(),b.begin()+32),"report ID mismatch");return c;}
Bytes bundle(const Bytes&c){Bytes b;varint(b,1);varint(b,c.size());b.insert(b.end(),c.begin(),c.end());return b;}
Bytes readbundle(const Bytes&b){size_t at=0;require(readvar(b,at)==1,"output count");auto l=readvar(b,at);require(l==b.size()-at,"output length");return Bytes(b.begin()+at,b.end());}
