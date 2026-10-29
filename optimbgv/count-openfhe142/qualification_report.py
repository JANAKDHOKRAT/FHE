from pathlib import Path
import json,re,subprocess,os
root=Path(__file__).resolve().parent;r=Path('/workspace/fhe-validation/count-openfhe142-2026-10-28')
def counts(path):
 text=path.read_text();rows=re.findall(r'test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored;',text)
 assert rows and all(a=='ok'and int(c)==0 for a,b,c,d in rows),path
 return {'passed':sum(int(b)for a,b,c,d in rows),'ignored':sum(int(d)for a,b,c,d in rows)}
w=counts(r/'wrapper-final-tests.log');c=counts(r/'count-tests.log')
completed=json.loads((r/'integration-completed.json').read_text());manifest=json.loads((r/'integration-programs.json').read_text())
assert set(x['name']for x in completed)==set(x['name']for x in manifest)-{'batch_noise'}
serial=(r/'prio3-tests.log').read_text();assert '55 passed; 0 failed' in serial
batch=serial.split('Running tests/batch_noise.rs',1)[1].split('Running tests/bounds.rs',1)[0];assert '1 passed; 0 failed' in batch
allnames={x['name']:x for x in manifest};env={**os.environ,'LD_LIBRARY_PATH':'/workspace/fhe-deps/install-1.4.2/lib'}
for x in completed:
 assert x['exit_code']==0 and x['outcomes']and all(y['failed']==0 for y in x['outcomes'])
 names=subprocess.check_output([x['executable'],'--list'],env=env,text=True)
 expected=sum(': test' in s for s in names.splitlines())
 assert sum(y['passed']+y['failed']+y['ignored']for y in x['outcomes'])==expected,(x['name'],expected)
p=55+1+sum(y['passed']for x in completed for y in x['outcomes']);ignored=sum(y['ignored']for x in completed for y in x['outcomes'])
subprocess.run(['python3',str(root/'verify_originals.py')],check=True)
result={'status':'scoped compatibility qualification passed','openfhe':'1.4.2','wrapper':w,'fhe_prio3':{'passed':p,'ignored':ignored,'retained_completed_integration_program':'batch_noise','unit_tests_retained':55,'other_programs':len(completed)},'count_core':c,'profile':{'p':65537,'ring':32768,'depth':18,'key_switch_digits':7,'groups':4,'max_batch':32,'report_bytes':6176895,'full_Q_QP_match_previous_profile':True},'production_security_certified':False,'note':'Original1.3.1 code and professor1.4.2 artifact preserved. Existing protocol/malicious-ciphertext/circuit-privacy limitations unchanged. Ignored pre-existing measurement is not a pass.'}
(r/'qualification.json').write_text(json.dumps(result,indent=2)+'\n');(root/'QUALIFICATION.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
