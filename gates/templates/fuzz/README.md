# Fuzz targets

Copy `fuzz/` into the target workspace and run `cargo fuzz build` once to check it links.

These targets exist for one reason the ordinary test suite cannot cover: a test suite only tries
the inputs somebody thought of. When nobody writes the code by hand, "somebody thought of it"
means the model thought of it, and a model that introduced a parsing bug is unlikely to have
written the test that finds it. A fuzzer does not share the author's blind spots.

## What the flags are for

Every target runs with three limits, and each one turns a class of denial-of-service into an
ordinary, reproducible crash file:

- `-timeout=2` — an input that takes more than two seconds is a finding, not a slow test. This is
  how a quadratic path or a catastrophic regex shows up before someone finds it in production.
- `-rss_limit_mb=1024` and `-malloc_limit_mb=256` — an input that allocates without bound is a
  finding. The usual shape is a length field the caller controls being trusted as a capacity.
- `-max_len` — matched to each format's documented limit, so the fuzzer spends its time inside
  the range the code actually claims to handle.

## The oracle matters more than the fuzzer

A target that only checks "did not panic" finds crashes and nothing else. Silent corruption — the
database returning a wrong answer rather than falling over — is the worse bug and the one a
differential oracle catches. So the stateful targets below run the real engine and a dead-simple
model side by side and compare after every operation. The model is deliberately too slow and too
simple to ship, which is exactly what makes it trustworthy as a reference.

## Targets

| Target | Oracle |
| --- | --- |
| `json_parse` | No panic; depth and size limits hold for both arrays and objects; parse → serialise → parse is stable |
| `wal_recover` | A truncated or corrupt log returns an error. It never panics, never over-allocates, and never silently drops a committed record |
| `engine_ops` | A sequence of put/get/delete is compared against a `BTreeMap` after every step |
| `vector_index` | Approximate search recall stays within bounds of exact brute-force search over the same set |
| `crdt_merge` | Merging the same operations in any order on any replica converges to the same state |

## Running them

```bash
cargo fuzz run json_parse -- -timeout=2 -rss_limit_mb=1024 -max_len=1048576
```

Every crash or timeout input found becomes a permanent regression test under
`tests/regressions/`, replayed by the ordinary test suite. The corpus only grows: a case that
once failed is never deleted, because the point of keeping it is that someone will eventually
reintroduce the bug.
