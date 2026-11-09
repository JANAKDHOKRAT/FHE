import unittest
from parameters import profile
class Guards(unittest.TestCase):
 def test_small_field_cannot_support_bound_16(self):
  r=profile(65537,16,650,8192)
  self.assertEqual(r['wrap_bound'],256)
  self.assertIn('p >= 2600*wrap_bound required',r['failures'])
 def test_field_boundary(self):
  # These synthetic integers test the inequality only, not field primality.
  self.assertIn('p >= 2600*wrap_bound required',profile(665599,16,650,8192)['failures'])
  self.assertNotIn('p >= 2600*wrap_bound required',profile(665600,16,650,8192)['failures'])
 def test_encoded_capacity(self):
  r=profile(4293918721,16,650,4096)
  self.assertEqual(r['encoded_input_elements'],1668)
  self.assertFalse(r['failures'])
  self.assertTrue(profile(4293918721,16,10000,8192)['failures'])
 def test_invalid(self):
  with self.assertRaises(ValueError):profile(65537,0,650,8192)
if __name__=='__main__':unittest.main()
