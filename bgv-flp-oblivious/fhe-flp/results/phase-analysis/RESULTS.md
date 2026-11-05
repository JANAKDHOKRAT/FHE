# Honest-phase and phase-smoothing diagnostic

Bounds are derived from the inspected 1.3.1 source and exact measured context moduli. Noise observations only check samples against those bounds. No observed maximum is used to choose a bound.

| p | Dense products summed | Derived final phase bound | Observed phase (one product) | Per-coefficient phase-only bits | Whole-vector phase-only bits | 64-bit vector bound certified? |
|---:|---:|---:|---:|---:|---:|---|
| 65537 | 1 | 37312389720 | 37041439275 | 50.71 | 37.71 | False |
| 65537 | 2 | 37312389720 | 37041439275 | 49.71 | 36.71 | False |
| 65537 | 13 | 37312389720 | 37041439275 | 47.01 | 34.01 | False |
| 4293918721 | 1 | 86475101565988669 | 86421230095429090 | 69.71 | 56.71 | False |
| 4293918721 | 2 | 86475101565988669 | 86421230095429090 | 68.71 | 55.71 | False |
| 4293918721 | 13 | 86475101565988669 | 86421230095429090 | 66.01 | 53.01 | False |

The 13-product row covers the dense-mask products in the L=100,n=1024 final correction at ring 8192. The observed phase column always comes from the separate one-product probe, not a measurement of 13 products.

Neither current profile certifies 64-bit whole-vector phase smoothing under this conservative bound. This is failure of this sufficient bound, not proof that the actual statistical distance exceeds 2^-64, and not proof that all other analyses/protocols are impossible.

Reducing the flood width by k bits subtracts k from the displayed phase-smoothing budgets. It cannot make a failing bound pass. Repeated objects and key lifetimes require further composition accounting.

Even a passing phase-smoothing bound would not establish full ciphertext circuit privacy: the ciphertext includes c1, whose distribution is not randomized by adding noise to c0. A complete argument or a separately justified ciphertext sanitization mechanism is required.

A phase threshold is also not a proof of authorized computation. Real-ciphertext tests show zero-phase aggregate substitution and modular doubling returning from a high phase to magnitude one. The proposed attack-detection probability cannot be asserted for arbitrary malicious ciphertexts.
