"""Independent integer oracle checks; these are NOT encrypted-circuit tests."""
import itertools
import json
import random

p = 65537
assert all(p % d for d in range(2, 257))
for x in range(p):
    assert 1 - pow(x, p-1, p) == int(x == 0)

# Distinct equality lookups follow by translation: x-a also ranges over F_p.
# Check every canonical chunk and every bit against its binary representation.
count = 0
for width in range(1, 14):
    for x in range(1 << width):
        bits = [(x >> k) & 1 for k in range(width)]
        assert sum(b << k for k, b in enumerate(bits)) == x
        count += 1

rng = random.Random(20261028)
vectors = 0
for length in [10, 25, 50, 100]:
    widths = [min(13, length-h) for h in range(0, length, 13)]
    for trial in range(128):
        chunks = [rng.randrange(1 << b) for b in widths]
        if trial % 2:
            h = trial % len(chunks)
            chunks[h] = rng.choice([1 << widths[h], p-1])
        flags = [int(x < (1 << b)) for x, b in zip(chunks, widths)]
        actual = []
        for h, (x, width) in enumerate(zip(chunks, widths)):
            for k in range(width):
                d = ((x >> k) & 1) if flags[h] else 0
                other = 1
                for j, v in enumerate(flags):
                    if j != h:
                        other *= v
                actual.append(d * other)
        expected = [((x >> k) & 1) for x,b in zip(chunks,widths) for k in range(b)] if all(flags) else [0]*length
        assert actual == expected
        vectors += 1

print(json.dumps({"status":"ALGEBRA_ORACLE_PASS", "prime_tested":p,
                  "equality_field_elements":p,"canonical_chunk_values":count,
                  "vector_cases":vectors,"encrypted_tests":False}))
