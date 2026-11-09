import ast
import math
from pathlib import Path
import unittest
from encoding import encode_float,encode_gradient_and_norm
# Execute only the original standalone rounding function for differential tests.
source=Path(__file__).parents[1]/'upstream/poc/flp_pine.py'
tree=ast.parse(source.read_text())
node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='encode_float')
namespace={}
exec(compile(ast.Module(body=[node],type_ignores=[]),str(source),'exec'),namespace)
class Encoding(unittest.TestCase):
 def test_upstream_rounding(self):
  for f in (0,1,7,16,32):
   for k in range(-1000,1001):
    x=(k+0.5)/2**f
    self.assertEqual(encode_float(x,f,4293918721),namespace['encode_float'](x,f)%4293918721)
 def test_hostile_floats(self):
  for x in (float('nan'),float('inf'),-float('inf'),5e-324,-5e-324):
   with self.assertRaises(ValueError):encode_float(x,7,4293918721)
 def test_norm_witness(self):
  encoded=encode_gradient_and_norm([3.0,-4.0],0,4293918721,5)
  self.assertEqual(encoded[:2],[3,4293918717])
  self.assertEqual(sum(b<<i for i,b in enumerate(encoded[2:7])),25)
  self.assertEqual(encoded[7:],[0]*5)
 def test_scaling_overflow(self):
  with self.assertRaises(ValueError):encode_float(1.7e308,127,4293918721)
if __name__=='__main__':unittest.main()
