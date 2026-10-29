# Selected original-encoding results

Generated only after all eight selected native cases and the final
length-100 Rust aggregate inspection passed. These are finite
correctness results; the production-security gate remains NOT GREEN.

All cases use p=65,537 and ring dimension32,768. Sum uses the original
seven weighted bits, vectors use individual bits, and histograms use
one-hot vectors. Unused slots remain ignored. Profiles differ by task.

| Task | Client report bytes | Evaluation-key bytes | Reports | Slot checks |
|---|---:|---:|---:|---:|
| count (1 encoded coordinates) | 5,578,879 | 199,258,085 | 5 | 16 |
| sum (7 encoded coordinates) | 6,340,735 | 726,766,219 | 5 | 46 |
| histogram (3 encoded coordinates) | 5,881,983 | 660,697,159 | 5 | 26 |
| sumvec (10 encoded coordinates) | 6,652,031 | 795,981,403 | 5 | 61 |
| sumvec (25 encoded coordinates) | 7,086,207 | 2,219,081,020 | 5 | 136 |
| sumvec (50 encoded coordinates) | 7,389,311 | 4,228,417,619 | 5 | 261 |
| histogram (8 encoded coordinates) | 6,488,191 | 795,981,379 | 5 | 51 |
| sumvec (100 encoded coordinates) | 7,405,695 | 6,397,146,236 | 4 | 430 |

Length100 emits 1 final ciphertext,
measured as 557,116 collector-output bytes.

The length100 case uses the documented isolated OpenFHE prime-selector
patch. The other rows use stock OpenFHE1.4.2; Histogram8 is a retained
earlier run. No new matched runtime or peak-memory comparison is claimed.

Several uploads exceed their corresponding published lookup references. Evaluation
keys are below the selected corresponding lookup references. This is
a trade-off, not a universal report-size or performance win.

The library128-bit target is enabled, but independent attack estimates
must be disclosed. In particular, recorded length100 primal-uSVP estimates
are about92.86 ADPS16 bits and126.10 MATZOV bits, not a128-bit certification.
Arbitrary-ciphertext robustness, collector circuit privacy and a complete
negligible-decryption-failure argument remain unresolved.

Raw evidence and hashes: evidence/qualification.json and
evidence/public-fixtures.json. See README.md and REPRODUCE.md.
