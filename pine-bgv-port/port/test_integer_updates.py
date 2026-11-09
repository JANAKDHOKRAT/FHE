import unittest
from fractions import Fraction
from itertools import product
from integer_updates import quantize,decode_aggregate
class IntegerUpdates(unittest.TestCase):
 def test_rounding_can_increase_norm(self):
  # ||(.6,.6)|| < 1, but rounding gives (1,1), whose norm > 1.
  with self.assertRaises(ValueError):quantize([Fraction(3,5)]*2,0,1)
 def test_ties_and_signs(self):
  self.assertEqual(quantize([Fraction(1,2),Fraction(3,2),Fraction(-3,2)],0,3),[0,2,-2])
 def test_exhaustive_small_aggregates(self):
  vectors=[v for v in product(range(-2,3),repeat=2) if sum(x*x for x in v)<=4]
  for a,b in product(vectors,repeat=2):
   total=[a[i]+b[i] for i in range(2)]
   self.assertEqual(decode_aggregate([v%17 for v in total],modulus=17,bound=2,submitted=2,fractional_bits=1),[Fraction(v,4) for v in total])
 def test_wrap_guard_and_noncanonical(self):
  with self.assertRaises(ValueError):decode_aggregate([0],modulus=17,bound=3,submitted=3,fractional_bits=0)
  with self.assertRaises(ValueError):decode_aggregate([17],modulus=17,bound=2,submitted=2,fractional_bits=0)
 def test_rejections_still_use_submitted_denominator(self):
  self.assertEqual(decode_aggregate([2],modulus=17,bound=2,submitted=4,fractional_bits=0),[Fraction(1,2)])
if __name__=='__main__':unittest.main()
