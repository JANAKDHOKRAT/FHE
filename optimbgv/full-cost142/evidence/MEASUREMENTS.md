# Full-core cost observations

one fresh setup and one N=4 batch per case; all roles serial, one thread; no network/DAP wrapper; alternative BGV encodings; no security certificate

Times are seconds per four-report batch; setup is one-time. RSS is whole-process GiB, not isolated server RAM. One diagnostic observation per configuration.

| Task | Backend | Report B/client | Collector output B/batch | Setup s | Client s/batch | Server s/batch | Collector s/batch | Peak RSS GiB |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| count | prio | 80 | 16 | 4.1152e-05 | 6.4988e-05 | 6.1222e-05 | 3.3e-07 | 0.010 |
| count | boolean | 8,245 | 12,189 | 3.2489 | 0.0110047 | 3.0975 | 2.5358e-05 | 1.207 |
| count | bgv | 6,176,895 | 581,724 | 14.3073 | 0.361889 | 2.54796 | 0.00627054 | 0.811 |
| sum(100) | prio | 216 | 16 | 4.2934e-05 | 6.9185e-05 | 4.7672e-05 | 5e-07 | 0.010 |
| sum(100) | bgv | 6,176,895 | 581,692 | 25.2815 | 0.364839 | 23.2215 | 0.00555597 | 1.993 |
| histogram(3) | prio | 352 | 96 | 0.000234663 | 0.000113812 | 0.000115875 | 9.91e-07 | 0.010 |
| histogram(3) | bgv | 6,176,895 | 581,692 | 20.6209 | 0.348303 | 23.8345 | 0.00713434 | 1.466 |
| histogram(8) | prio | 496 | 256 | 4.2124e-05 | 0.000309876 | 0.00011249 | 9.61e-07 | 0.010 |
| histogram(8) | bgv | 6,176,895 | 581,692 | 21.3087 | 0.457701 | 24.0637 | 0.00593908 | 1.466 |
| sumvec(10) | prio | 560 | 320 | 4.1032e-05 | 0.000142024 | 0.000377419 | 1.142e-06 | 0.010 |
| sumvec(10) | boolean | 82,261 | 121,781 | 3.5065 | 0.109864 | 32.9104 | 0.000107072 | 1.207 |
| sumvec(10) | bgv | 6,176,895 | 9,011,791 | 31.2851 | 0.358164 | 112.001 | 0.0953797 | 2.444 |
| sumvec(25) | prio | 928 | 800 | 3.961e-05 | 0.000159269 | 0.000128484 | 1.151e-06 | 0.010 |
| sumvec(25) | boolean | 205,621 | 304,421 | 3.12258 | 0.275776 | 71.0987 | 0.000241915 | 1.207 |
| sumvec(25) | bgv | 6,176,895 | 14,542,276 | 28.4103 | 0.389841 | 261.945 | 0.14242 | 2.444 |
| sumvec(50) | prio | 1,456 | 1,600 | 4.4317e-05 | 0.000255245 | 0.000160021 | 1.733e-06 | 0.010 |
| sumvec(50) | boolean | 411,221 | 608,821 | 3.00573 | 0.476494 | 136.504 | 0.00055765 | 1.207 |
| sumvec(50) | bgv | 6,496,383 | 29,084,551 | 72.8639 | 0.414134 | 1175.6 | 0.271643 | 7.109 |
| sumvec(100) | prio | 2,480 | 3,200 | 4.8383e-05 | 0.000285991 | 0.000340263 | 3.064e-06 | 0.010 |
| sumvec(100) | boolean | 822,421 | 1,217,621 | 3.13708 | 0.957657 | 273.612 | 0.00119361 | 1.207 |
| sumvec(100) | bgv | 6,815,871 | 58,169,101 | 78.7512 | 0.38011 | 2763.46 | 0.656488 | 7.779 |

Boolean Sum/Histogram cells are unavailable: the supplied professor implementation has no complete corresponding validator. No substituted design was benchmarked.

Prio3 report bytes are public plus both input shares, excluding nonce/HPKE/DAP framing; its raw log separately accounts for duplicated public shares and nonces. FHE reports use their prototype formats. Collector bytes are actual serialized output bundles (or the sum of two Prio3 share messages), excluding transport.

Completed 21/21 configurations; pending: none. No stable-throughput, deployment-cost or security-equivalence claim.
