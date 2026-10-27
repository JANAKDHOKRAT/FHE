#!/usr/bin/env python3
"""Negative checks: fabricated/incomplete evidence must not get a local pass."""
import hashlib,json,pathlib,shutil,subprocess,tempfile,unittest
R=pathlib.Path(__file__).resolve().parent
class EvidenceChecks(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='count-evidence-');self.out=pathlib.Path(self.tmp.name)/'evidence';shutil.copytree(R/'evidence',self.out)
  self.m=json.loads((self.out/'manifest.json').read_text())
  for entry in [self.m['algebra'],*self.m['profiles'].values(),*self.m['runs']]:
   rel=pathlib.Path(entry['log']).relative_to('evidence');entry['log']=str(self.out/rel)
  self.save()
 def tearDown(self):self.tmp.cleanup()
 def save(self):(self.out/'manifest.json').write_text(json.dumps(self.m))
 def summarize(self):return subprocess.run(['python3',str(R/'summarize.py'),'--evidence',str(self.out)],stdout=subprocess.PIPE,stderr=subprocess.PIPE).returncode
 def test_valid_evidence(self):self.assertEqual(self.summarize(),0)
 def test_incomplete_rejected(self):self.m['status']='running';self.save();self.assertNotEqual(self.summarize(),0)
 def test_missing_profile_rejected(self):self.m['profiles'].pop(next(iter(self.m['profiles'])));self.save();self.assertNotEqual(self.summarize(),0)
 def test_tampered_measurement_rejected(self):
  r=self.m['runs'][0];p=self.out/r['profile']/f"key-{r['key']}.json";d=json.loads(p.read_text());d['report_bytes']+=8;p.write_text(json.dumps(d));self.assertNotEqual(self.summarize(),0)
 def test_size_lie_with_updated_hash_rejected(self):
  r=self.m['runs'][0];p=self.out/r['profile']/f"key-{r['key']}.json";d=json.loads(p.read_text());d['report_bytes']+=8;p.write_text(json.dumps(d));r['measurement_sha256']=hashlib.sha256(p.read_bytes()).hexdigest();self.save();self.assertNotEqual(self.summarize(),0)
 def test_wrong_extended_modulus_rejected(self):
  r=self.m['runs'][0];p=self.out/r['profile']/f"key-{r['key']}.json";d=json.loads(p.read_text());d['key_switch_moduli_decimal']=[str(1<<2000)];p.write_text(json.dumps(d));r['measurement_sha256']=hashlib.sha256(p.read_bytes()).hexdigest();self.save();self.assertNotEqual(self.summarize(),0)
 def test_existing_output_never_overwritten(self):
  p=self.out/'manifest.json';before=p.read_bytes();res=subprocess.run(['python3',str(R/'run_study.py'),'--out',str(self.out)],stdout=subprocess.PIPE,stderr=subprocess.PIPE);self.assertNotEqual(res.returncode,0);self.assertEqual(p.read_bytes(),before)
if __name__=='__main__':unittest.main(verbosity=2)
