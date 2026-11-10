#!/usr/bin/env python3
"""Fetch the real UCI handwritten digits copy distributed with scikit-learn.

1797 rows, 64 pixels and a label; no generated examples. Data origin and
license: https://archive.ics.uci.edu/dataset/80/optical+recognition+of+handwritten+digits
CC BY 4.0, E. Alpaydin and C. Kaynak, doi:10.24432/C50P49.
The pinned scikit-learn copy is verified BEFORE decompression.
"""
import gzip
import hashlib
from pathlib import Path
import sys
import urllib.request

URL = "https://raw.githubusercontent.com/scikit-learn/scikit-learn/1.7.2/sklearn/datasets/data/digits.csv.gz"
SHA256 = "09f66e6debdee2cd2b5ae59e0d6abbb73fc2b0e0185d2e1957e9ebb51e23aa22"
if len(sys.argv) != 2:
    raise SystemExit("usage: fetch_training_digits.py NEW_OUTPUT_CSV")
with urllib.request.urlopen(URL, timeout=60) as response:
    data = response.read(1000000)
if hashlib.sha256(data).hexdigest() != SHA256:
    raise SystemExit("dataset digest mismatch")
with Path(sys.argv[1]).open("xb") as output:
    output.write(gzip.decompress(data))
print(SHA256, URL)
