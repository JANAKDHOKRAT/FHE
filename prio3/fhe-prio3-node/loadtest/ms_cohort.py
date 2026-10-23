#!/usr/bin/env python3
"""Measurement files for the load test from a real dataset.

The dataset: Muslim et al., "Brain MRI dataset of multiple sclerosis with
consensus manual lesion segmentation and patient meta information", Data in
Brief 42 (2022) 108139; data: Mendeley Data, doi:10.17632/8bctsm8jz7.1,
CC BY 4.0. Its zip holds "Supplementary Table 1 for patient info .xlsx":
one row per patient (60), with the patient's ID and EDSS among the columns.

This script reads that table from the zip (after checking the zip's SHA-256
against the value Mendeley publishes) with the standard library only, and
writes one measurement file per binning for `loadtest/run.sh --measurements`:

  * edss3: the three severity classes of Cirillo et al. (TADATA 2025):
    normal EDSS <= 2.0, mild 2.5 to 4.0, severe > 4.0
    (`histogram:0`, `histogram:1`, `histogram:2`);
  * edss21: one bin per half point of the scale, 0, 0.5, ..., 10
    (`histogram:i` for EDSS i/2).

Every EDSS value must be a multiple of 0.5 in [0, 10]; any other value stops
the script (nothing is rounded or guessed). The dataset records 0.5 for some
patients, which is not a step of Kurtzke's scale (0, 1.0, 1.5, ...); it is
kept as recorded: class "normal" in edss3, bin 1 in edss21.

Patients are split across simulated hospitals by a fixed rule: the patients
in ID order, cut into `--hospitals` contiguous blocks of equal size
(`hospital-1` holds IDs 1 to 15 with four hospitals). Each line of a file is
`hospital-k histogram:b`; run.sh enrolls each hospital as a sender.

Next to each file, `<name>.expected.txt` gives the plaintext counts per bin
and per hospital, computed here independently of the load test's own check.

Usage: ms_cohort.py ZIP OUTDIR [--hospitals 4]
"""

import argparse
import hashlib
import re
import sys
import zipfile
import xml.etree.ElementTree as ET
from fractions import Fraction

DATASET_SHA256 = "c90f0f47c9e1a5e0fafc87b77dfcbcb09ac0cf9ffdaa333aaec1b9c63d31a7b3"
TABLE = "Supplementary Table 1 for patient info .xlsx"
NS = {
    "m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
    "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    "pr": "http://schemas.openxmlformats.org/package/2006/relationships",
}


def fail(msg):
    sys.exit(f"ms_cohort: {msg}")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def col_index(ref):
    n = 0
    for ch in re.match(r"[A-Z]+", ref).group(0):
        n = n * 26 + ord(ch) - 64
    return n - 1


def first_sheet_rows(xlsx_bytes):
    """Rows of the workbook's first sheet: (row number, {column: text})."""
    import io

    z = zipfile.ZipFile(io.BytesIO(xlsx_bytes))
    shared = []
    if "xl/sharedStrings.xml" in z.namelist():
        for si in ET.fromstring(z.read("xl/sharedStrings.xml")).findall("m:si", NS):
            shared.append("".join(t.text or "" for t in si.iter("{%s}t" % NS["m"])))
    wb = ET.fromstring(z.read("xl/workbook.xml"))
    rels = {
        r.get("Id"): r.get("Target")
        for r in ET.fromstring(z.read("xl/_rels/workbook.xml.rels")).findall("pr:Relationship", NS)
    }
    sheet = wb.find("m:sheets", NS)[0]
    target = rels[sheet.get("{%s}id" % NS["r"])]
    path = "xl/" + target.lstrip("/").removeprefix("xl/")
    rows = []
    for row in ET.fromstring(z.read(path)).iter("{%s}row" % NS["m"]):
        cells = {}
        for c in row.findall("m:c", NS):
            t, v = c.get("t"), c.find("m:v", NS)
            if t == "s":
                val = shared[int(v.text)]
            elif t == "inlineStr":
                val = "".join(x.text or "" for x in c.iter("{%s}t" % NS["m"]))
            else:
                val = v.text if v is not None else ""
            cells[col_index(c.get("r"))] = val.strip()
        rows.append((int(row.get("r")), cells))
    return rows


def patients(zip_path):
    """(id, EDSS as an exact Fraction) for every patient row."""
    got = sha256(zip_path)
    if got != DATASET_SHA256:
        fail(f"{zip_path}: SHA-256 {got}, expected the published {DATASET_SHA256}")
    with zipfile.ZipFile(zip_path) as z:
        if TABLE not in z.namelist():
            fail(f"{TABLE!r} is not in the zip")
        rows = first_sheet_rows(z.read(TABLE))
    header_row = next((cells for _, cells in rows if cells.get(0) == "ID"), None)
    if header_row is None:
        fail("no header row starting with 'ID'")
    columns = {name: i for i, name in header_row.items()}
    if "EDSS" not in columns:
        fail(f"no EDSS column in the header: {sorted(columns)}")
    id_col, edss_col = 0, columns["EDSS"]
    out, seen = [], set()
    header_seen = False
    for r, cells in rows:
        if cells is header_row:
            header_seen = True
            continue
        if not header_seen or not any(cells.values()):
            continue
        raw_id, raw_edss = cells.get(id_col, ""), cells.get(edss_col, "")
        if not raw_id.isdigit():
            fail(f"row {r}: patient ID {raw_id!r} is not a number")
        pid = int(raw_id)
        if pid in seen:
            fail(f"row {r}: patient ID {pid} repeated")
        seen.add(pid)
        try:
            edss = Fraction(raw_edss)
        except (ValueError, ZeroDivisionError):
            fail(f"row {r}: EDSS {raw_edss!r} is not a number")
        if not (0 <= edss <= 10) or (edss * 2).denominator != 1:
            fail(f"row {r}: EDSS {raw_edss} is not a multiple of 0.5 in [0, 10]")
        out.append((pid, edss))
    if not out:
        fail("no patient rows")
    return sorted(out)


def edss3(e):
    if e <= 2:
        return 0
    if e <= 4:
        return 1
    return 2


def edss21(e):
    return int(e * 2)


BINNINGS = {
    "edss3": (3, edss3, ["normal (<= 2.0)", "mild (2.5-4.0)", "severe (> 4.0)"]),
    "edss21": (21, edss21, [f"EDSS {Fraction(i, 2).numerator / Fraction(i, 2).denominator:g}" for i in range(21)]),
}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("zip")
    ap.add_argument("outdir")
    ap.add_argument("--hospitals", type=int, default=4)
    a = ap.parse_args()
    pts = patients(a.zip)
    n = len(pts)
    if a.hospitals < 1 or n % a.hospitals:
        fail(f"{n} patients do not split into {a.hospitals} equal blocks")
    block = n // a.hospitals
    hospital = {pid: f"hospital-{i // block + 1}" for i, (pid, _) in enumerate(pts)}
    import os

    os.makedirs(a.outdir, exist_ok=True)
    recorded = sorted({e for _, e in pts})
    print(f"{n} patients; recorded EDSS values: {', '.join(f'{float(e):g}' for e in recorded)}")
    for name, (length, bin_of, labels) in BINNINGS.items():
        lines = [f"# {name}: Muslim et al. 2022 (doi:10.17632/8bctsm8jz7.1), zip sha256 {DATASET_SHA256}",
                 f"# one report per patient in ID order; {a.hospitals} hospitals of {block} patients (contiguous ID blocks)"]
        counts = [0] * length
        per_h = {}
        for pid, e in pts:
            b = bin_of(e)
            counts[b] += 1
            h = hospital[pid]
            per_h.setdefault(h, [0] * length)[b] += 1
            lines.append(f"{h} histogram:{b}")
        path = os.path.join(a.outdir, f"{name}.txt")
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")
        exp = [f"type histogram:{length}", f"reports {n}", "bin\tlabel\tcount"]
        exp += [f"{b}\t{labels[b]}\t{c}" for b, c in enumerate(counts)]
        exp.append("per hospital: " + "; ".join(f"{h} {sum(v)} reports" for h, v in sorted(per_h.items())))
        with open(os.path.join(a.outdir, f"{name}.expected.txt"), "w") as f:
            f.write("\n".join(exp) + "\n")
        print(f"{name}: histogram:{length}, counts {counts} -> {path}")


if __name__ == "__main__":
    main()
