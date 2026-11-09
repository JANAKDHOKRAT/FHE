"""PINE fixed-point boundary, pinned to upstream 4d11ac8 encode_float.
No proof, encrypted verification, or release API is supplied by this module.
"""
import math
import sys

def encode_float(value, fractional_bits, modulus):
    if type(fractional_bits) is not int or not 0 <= fractional_bits < 128:
        raise ValueError('fractional_bits must be an integer in [0,128)')
    if type(modulus) is not int or modulus < 3:
        raise ValueError('invalid field modulus')
    if type(value) is not float:
        raise TypeError('expected IEEE-754 float64')
    if not math.isfinite(value) or (value != 0 and abs(value) < sys.float_info.min):
        raise ValueError('nonfinite or subnormal input')
    scaled=value * 2**fractional_bits
    if not math.isfinite(scaled):
        raise ValueError('fixed-point scaling overflow')
    return round(scaled) % modulus

def encode_gradient_and_norm(values, fractional_bits, modulus, bound):
    if type(bound) is not int or bound <= 0 or modulus <= 3*bound*bound+2:
        raise ValueError('norm range parameters outside PINE guard')
    gradient=[encode_float(x,fractional_bits,modulus) for x in values]
    norm=sum(x*x for x in gradient)%modulus
    complement=(bound*bound-norm)%modulus
    width=(bound*bound).bit_length()
    def bits(x):
        if x >= 1 << width:
            raise ValueError('norm witness does not fit')
        return [(x>>i)&1 for i in range(width)]
    return gradient+bits(norm)+bits(complement)
