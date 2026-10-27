# First study: results and limits

The recorded experiment is a Count-exact context-mode ablation, with broader
baseline correctness qualification. It is not an exhaustive parameter search,
proof of minimality, security audit, or production deployment.

## Findings established by the encrypted tests

* The retained flooding profile passes the new full Count test and existing
  complete SumVec exact, Histogram exact and bounded Sum randomized tests.
* Direct omission of the flooding setting fails before application evaluation:
  the inherited rebuild guard requires depth+3 towers; this profile has 26
  towers for circuit depth 24.
* Adding one requested context level clears that structural issue, but the
  startup rebuild/threshold-decryption self-test then returns an incorrect
  value for a fresh ciphertext. This candidate is also rejected.
* Neither rejected profile has a benchmark result or an approved security claim.
  A failed startup test does not establish that native single-key BGV needs
  flooding, nor does it by itself identify the library, reconstruction, fusion
  or parameter choice as the root cause.

The current single-collector application inherits one-party threshold setup,
while its packed-wire verification uses throwaway two-party threshold keys.
Changing one context setting is not equivalent to implementing and qualifying a
native single-key path. Do not weaken the shared threshold self-test to obtain
smaller files. The retained configuration is unchanged.

## What must happen before the next optimization claim

1. Implement a separate native single-key path, including appropriate key
   generation and a complete rebuild/evaluate/decrypt startup test. Preserve
   the threshold API's guards. Specify collector leakage and scope security
   assumptions before adopting different decryption protections.
2. Derive field/layout/depth profiles jointly. The current exact implementation
   fixes a 32768-slot row: a smaller ring is not a drop-in change. Validate
   active-slot isolation, all output positions, aggregate bounds, and complete
   circuits before timing smaller-field profiles.
3. For randomized profiles, declare the invalid-attempt bound Q and global
   target, and choose repetitions from Q*p^(-t), not the encryption-security
   label. Count-exact qualification does not establish those profiles.
4. Expand workload-specific invalid/boundary tests and measure each admitted
   profile across independent keys, batch sizes and packing levels. Measure
   warm-up and control load before making precise performance claims.

The present successful timing samples measure Count exact only. Other task
qualification times are not workload benchmarks. See the recorded summary,
manifest, raw samples and logs for measured costs and exact execution conditions.
