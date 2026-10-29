"""Summarize primary successful executions; missing/incomplete cases fail closed."""
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
def read(name):
    return [json.loads(line) for line in (root/name).read_text().splitlines()]
def profile(rows):
    return next(r for r in rows if r["status"] == "PROFILE")

sum_rows = read("sum100-full.jsonl" if (root/"sum100-full.jsonl").exists() else "redesign-small-prime142.jsonl")
hist_rows = read("histogram.jsonl" if (root/"histogram.jsonl").exists() else "histogram_lookup.jsonl")
assert sum_rows[-1]["status"] == "ALL_SUM100_PASS"
assert sum_rows[-1]["reports"] == 40
assert [r["sum"] for r in sum_rows if r["status"]=="SUM100_PASS"] == [202,3200]
assert [r["length"] for r in hist_rows if r["status"]=="HISTOGRAM_PASS"] == [3,8]
reference = root/"count-profile-reference.json"
if not reference.exists():
    reference = pathlib.Path(__file__).resolve().parent/"evidence/count-profile-reference.json"
baseline = json.loads(reference.read_text())
for p in [profile(sum_rows),profile(hist_rows)]:
    for key in ["p","ring","depth","q","qp"]:
        assert p[key] == baseline[key],key

results = []
for length in [10,25,50,100]:
    name = "vector100-fixed.jsonl" if length==100 else ("vector50-stream.jsonl" if length==50 else f"vector{length}.jsonl")
    if not (root/name).exists():
        name=f"vector{length}.jsonl"
    rows = read(name)
    assert rows[-1]["status"] == "VECTOR_PASS",name
    p = profile(rows)
    assert p["p"]==65537 and p["ring"]==32768
    passes = [r for r in rows if r["status"]=="VECTOR_REPORT_PASS"]
    assert len(passes)==2 and [r["valid"] for r in passes]==[True,False]
    assert passes[0]["report_bytes"]==passes[1]["report_bytes"]
    formula = 127+(2*p["ring"]*sum(q.bit_length() for q in p["q"])+7)//8
    assert formula==passes[0]["report_bytes"]
    results.append({"length":length,"reports":2,"report_bytes":formula,
                    "profile":p,"tested_batch_size":2})

summary={"status":"PRIMARY_CIRCUITS_PASS","sum_reports":40,"histogram_reports":10,
         "vector_reports":8,"primary_reports_total":58,"sum_and_histogram_same_parameters_as_count":True,
         "vectors":results,"sum_profile":profile(sum_rows),"histogram_profile":profile(hist_rows),
         "production_security_certified":False,"independent_security_assessment_complete":False,
         "network_deployment_implemented":False,"speed_comparison_performed":False}
(root/"summary.json").write_text(json.dumps(summary,indent=2)+"\n")
print(json.dumps({k:v for k,v in summary.items() if k not in ["vectors","sum_profile","histogram_profile"]}))
for r in results:
    print("SumVec",r["length"],r["report_bytes"],"bytes",r["profile"]["rotation_key_bytes"],"rotation-key bytes")
