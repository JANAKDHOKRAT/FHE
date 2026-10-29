"""Verify recorded circuit evidence; never infer a task pass from setup alone."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def rows(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def exit_record(path, fields):
    records = [line.split() for line in path.read_text().splitlines()]
    matches = [line for line in records if line[:-1] == fields]
    assert len(matches) == 1 and matches[0][-1] == '0', (path, fields)


def reference_case(task, length, limit):
    """Check byte references against the published raw selected implementation."""
    logical_length = 1 if task in ('count', 'sum') else length
    path = ROOT.parent.parent / f'optimbgv/full-cost142/evidence/bgv-{task}-{logical_length}.jsonl'
    data = rows(path)
    assert data and data[-1]['status'] == 'PASS', path
    end = data[-1]
    assert end['evaluation_key_bytes'] == limit
    assert len(end['report_bytes']) == 4
    assert len(set(end['report_bytes'])) == 1 and end['report_bytes'][0] > 0
    return dict(raw_log=str(path.relative_to(ROOT.parent.parent)),
                raw_log_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                report_bytes=end['report_bytes'][0],
                note='Different encodings/profiles; Count reference packs four groups, new Count is per report')


def validate(path, task, length, reports, checks, limit):
    data = rows(path)
    assert data and data[-1]['status'] == 'EXPLORATORY_TASK_PASS', path
    assert not any(r['status'] == 'FAILED' for r in data), path
    end = data[-1]
    assert (end['task'], end['length'], end['reports'], end['slot_checks']) == (
        task, length, reports, checks), path
    assert end['final_task_decoding_qualified'] is True
    assert end['production_qualified'] is False
    params = [r for r in data if r['status'] == 'PARAMETERS_ONLY']
    assert len(params) == 1
    assert (params[0]['p'], params[0]['ring']) == (65537, 32768)
    assert params[0]['depth'] == 16 + length.bit_length()
    slots = [r for r in data if r['status'] == 'SLOT_CHECK']
    assert len(slots) == checks and all(r['mismatches'] == 0 for r in slots)
    admitted = [r for r in data if r['status'] == 'REPORT_PASS']
    assert len(admitted) == reports
    assert [r['report'] for r in admitted] == list(range(reports))
    assert any(r['valid'] for r in admitted) and any(not r['valid'] for r in admitted)
    moduli = [r for r in data if r['status'] == 'MODULI']
    assert len(moduli) == 1
    q = moduli[0]['q']
    assert len(q) == params[0]['depth'] + 2
    assert len(set(q)) == len(q) and all((v - 1) % 65536 == 0 for v in q)
    # Existing packed ciphertext + frozen Report container; not native Cereal size.
    expected_bytes = 127 + 8192 * sum((v - 1).bit_length() for v in q)
    assert end['report_bytes'] == expected_bytes, (path, expected_bytes)
    key_bytes = end['rotation_key_bytes'] + end['mult_key_bytes']
    assert key_bytes <= limit, (path, key_bytes, limit)
    return dict(task=task, length=length, status='FINITE_ENCRYPTED_QUALIFICATION_PASS',
                report_bytes=end['report_bytes'], evaluation_key_bytes=key_bytes,
                reference_lookup_evaluation_key_bytes=limit, reports=reports,
                slot_checks=checks, depth=params[0]['depth'],
                raw_log=str(path.relative_to(ROOT.parent.parent)),
                raw_log_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                reference=reference_case(task, length, limit),
                production_qualified=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--require-all', action='store_true')
    args = parser.parse_args()
    chosen = [
        ('count', 1, 'low-count-1.jsonl', 16, 242261163),
        ('sum', 7, 'low-sum-7.jsonl', 46, 1776581938),
        ('histogram', 3, 'low-histogram-3.jsonl', 26, 1211305863),
        ('sumvec', 10, 'low-sumvec-10.jsonl', 61, 2261104288),
        ('sumvec', 25, 'vector-25.jsonl', 136, 2261104288),
        ('sumvec', 50, 'vector-50.jsonl', 261, 6783150432),
    ]
    results = []
    for task, length, name, checks, limit in chosen:
        result = validate(ROOT / 'evidence' / name, task, length, 5, checks, limit)
        if length in (25, 50):
            exit_record(ROOT / 'evidence/exits.txt', [str(length)])
        else:
            exit_record(ROOT / 'evidence/low-exits.txt', [task, str(length)])
        results.append(result)
    old = ROOT / 'retained-histogram8/evidence'
    result = validate(old / 'histogram-full-digits.jsonl', 'histogram', 8, 5, 51, 1211305863)
    exit_record(old / 'full-digits-exits.txt', ['histogram', '8'])
    result['provenance_note'] = 'Prior run, not rerun for this table'
    results.append(result)

    active = ROOT / 'prime-diagnostic/vector100-late.jsonl'
    data = rows(active)
    process_path = active.with_suffix('.process.json')
    process = json.loads(process_path.read_text()) if process_path.exists() else None
    final_native = bool(data and data[-1]['status'] == 'EXPLORATORY_TASK_PASS')
    if final_native and process and process['returncode'] == 0:
        result = validate(active, 'sumvec', 100, 4, 430, 7429158368)
        final = data[-1]
        assert final['aggregate_ciphertexts'] == 1
        context = rows(ROOT / 'prime-diagnostic/context100-fast.jsonl')[0]
        actual = [r for r in data if r['status'] == 'MODULI'][0]
        assert actual['q'] == context['q'] and actual['qp_equals_q'] is True
        assert final['aggregate_wire_bytes'] > final['aggregate_ciphertext_bytes_sum'] > 0
        codec = rows(ROOT / 'evidence/rust-final-codec.jsonl')
        result['aggregate_wire_bytes'] = final['aggregate_wire_bytes']
        result['aggregate_ciphertexts'] = final['aggregate_ciphertexts']
        result['rust_aggregate_codec_checked'] = bool(
            codec and codec[-1].get('status') == 'FULL_CODEC_PASS'
            and codec[-1].get('aggregate_checked') is True
            and codec[-1].get('report_bytes') == final['report_bytes']
            and codec[-1].get('collector_output_bytes') == final['aggregate_wire_bytes']
            and codec[-1].get('negative_parser_cases') == 7)
        result['legacy_wrapper_status_mismatch'] = process.get('final_pass_record') is False
        if args.require_all:
            assert result['rust_aggregate_codec_checked'], 'Rust aggregate inspection missing'
        results.append(result)
    else:
        results.append(dict(task='sumvec', length=100,
                            status='NOT_COMPLETELY_QUALIFIED',
                            complete_reports=sum(r['status'] == 'REPORT_PASS' for r in data),
                            completed_slot_checks=sum(r['status'] == 'SLOT_CHECK' for r in data),
                            native_final_record=final_native, process=process))
        if args.require_all:
            raise SystemExit('NOT GREEN: length-100 qualification incomplete')
    print(json.dumps(dict(status='RESEARCH_EVIDENCE_SUMMARY', cases=results,
                          library_target='HEStd_128_classic',
                          encryption_security_proven=False,
                          production_security_gate='NOT GREEN'), indent=2))


if __name__ == '__main__':
    main()
