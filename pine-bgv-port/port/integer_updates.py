"""Exact integer-update checks and aggregate decoding.
Not a substitute for encrypted PINE verification. No floating-point norms.
"""
from fractions import Fraction

def quantize(values, fractional_bits, bound):
    """Round exact supplied rational values to nearest, ties to even.
    Caller must supply rationals; float-to-rational conversion is explicit.
    Reject after rounding if the integer vector exceeds bound.
    """
    if type(fractional_bits) is not int or not 0<=fractional_bits<128:
        raise ValueError('invalid scale')
    if type(bound) is not int or bound<=0 or not values:
        raise ValueError('invalid bound or empty vector')
    if any(not isinstance(v,(int,Fraction)) or isinstance(v,bool) for v in values):
        raise TypeError('supply exact integers or Fractions')
    q=[round(Fraction(v)*(1<<fractional_bits)) for v in values]
    if sum(v*v for v in q)>bound*bound:
        raise ValueError('rounded update exceeds integer norm bound')
    return q

def decode_aggregate(residues, *, modulus, bound, submitted, fractional_bits):
    """Decode an unweighted aggregate divided by submitted cohort size.
    Requires an upstream guarantee that each accepted update has norm <= bound;
    rejected contributions are zero. This function cannot verify that guarantee.
    Modulus primality and cryptographic parameters are checked elsewhere.
    """
    if any(type(v) is not int for v in (modulus,bound,submitted,fractional_bits)):
        raise TypeError('integer parameters required')
    if modulus<3 or modulus%2==0 or bound<=0 or submitted<=0 or not 0<=fractional_bits<128:
        raise ValueError('invalid parameters')
    if 2*submitted*bound>=modulus:
        raise ValueError('centered aggregate is not uniquely decodable')
    if not residues or any(type(v) is not int or not 0<=v<modulus for v in residues):
        raise ValueError('noncanonical aggregate')
    centered=[v if v<=modulus//2 else v-modulus for v in residues]
    if sum(v*v for v in centered)>(submitted*bound)**2:
        raise ValueError('aggregate outside necessary norm bound')
    denominator=submitted*(1<<fractional_bits)
    return [Fraction(v,denominator) for v in centered]
