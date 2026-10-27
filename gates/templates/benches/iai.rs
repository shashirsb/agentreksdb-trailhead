//! Instruction-count benchmarks for the `gate-perf / instructions` gate.
//!
//! Copy this into the target workspace as `benches/iai.rs` and register it:
//!
//! ```toml
//! [[bench]]
//! name = "iai"
//! harness = false
//! ```
//!
//! # Why instruction counts rather than wall time
//!
//! Wall time on a shared CI runner moves by several percent between runs for reasons that have
//! nothing to do with the code: a noisy neighbour, a different host, thermal throttling. A 2%
//! wall-time gate on that noise fails honest changes most of the time, and a gate that cries
//! wolf is a gate people learn to override. Counting retired instructions under Callgrind is
//! deterministic: the same code on the same input gives the same number on any machine, so a 2%
//! move is a real 2% move and blocking on it is fair.
//!
//! This costs coverage, not accuracy: instruction counts cannot see time spent waiting on I/O,
//! locks or the network. Those belong to the nightly wall-clock benchmarks on a fixed machine,
//! which this gate deliberately does not try to replace.
//!
//! # The two kinds of benchmark here
//!
//! **Fixed-size benchmarks** catch a change that makes an existing operation cost more.
//!
//! **Scaling pairs** — the same operation at `n` and at `4n` — catch something a percentage gate
//! structurally cannot: an algorithm that got worse. A fixture small enough to run in CI hides a
//! quadratic path, because at n=100 the difference is a rounding error. Comparing the cost at
//! `n` with the cost at `4n` exposes the exponent instead of the constant: linear work costs
//! about 4x, quadratic about 16x. A change that quietly turns a scan into a nested loop shows up
//! as a ratio, however small the fixture.
//!
//! That is also the shape of a deliberate denial-of-service: the attacker does not need to make
//! anything slow today, only to make it super-linear in something a caller controls. So the
//! inputs below are the adversarial ones — maximum nesting, many keys, colliding keys, maximum
//! record size — rather than the averages a performance suite would use.

use gungraun::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;

// ── Replace these with the real crate's entry points ─────────────────────────
// They are stand-ins so this file compiles and the gate is meaningful from day one. Each one
// should become the real parser, WAL, index or merge call.

fn parse(input: &str) -> usize {
    input.len()
}

fn merge(a: &[u64], b: &[u64]) -> usize {
    a.len() + b.len()
}

// ── Fixtures ─────────────────────────────────────────────────────────────────
// Built deterministically from a fixed seed: a benchmark whose input varies run to run measures
// the input, not the code.

fn flat_object(keys: usize) -> String {
    let mut s = String::from("{");
    for i in 0..keys {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!("\"k{i}\":{i}"));
    }
    s.push('}');
    s
}

/// Keys chosen to share a prefix, which is what a hash-collision attack looks like from the
/// outside: the caller controls the keys, and a map with a weak or fixed-seed hasher degrades
/// from constant to linear lookup under exactly this input.
fn colliding_object(keys: usize) -> String {
    let mut s = String::from("{");
    for i in 0..keys {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!("\"aaaaaaaaaaaaaaaa{i:08}\":1"));
    }
    s.push('}');
    s
}

fn nested(depth: usize) -> String {
    let mut s = String::new();
    for _ in 0..depth {
        s.push('[');
    }
    for _ in 0..depth {
        s.push(']');
    }
    s
}

fn sorted_ids(n: usize) -> Vec<u64> {
    (0..n as u64).collect()
}

// ── Fixed-size benchmarks ────────────────────────────────────────────────────

#[library_benchmark]
#[bench::small(flat_object(16))]
#[bench::medium(flat_object(1024))]
fn parse_object(input: String) -> usize {
    black_box(parse(black_box(&input)))
}

/// Deep nesting near whatever the documented limit is. The limit existing is not the same as the
/// limit being cheap: a parser that recurses can still burn the stack getting there.
#[library_benchmark]
#[bench::deep(nested(120))]
fn parse_deeply_nested(input: String) -> usize {
    black_box(parse(black_box(&input)))
}

// ── Scaling pairs: the denial-of-service gate ────────────────────────────────
//
// Each pair runs the same operation at n and 4n. Linear work lands near 4x. A ratio near 16x
// means the cost is quadratic in something the caller controls, which is a denial-of-service bug
// whether or not anyone put it there on purpose. The gate compares the ratio against the base
// commit, so the absolute number does not have to be pretty, only stable.

#[library_benchmark]
#[bench::n(flat_object(500))]
#[bench::n4(flat_object(2000))]
fn scale_parse_keys(input: String) -> usize {
    black_box(parse(black_box(&input)))
}

#[library_benchmark]
#[bench::n(colliding_object(500))]
#[bench::n4(colliding_object(2000))]
fn scale_parse_colliding_keys(input: String) -> usize {
    black_box(parse(black_box(&input)))
}

#[library_benchmark]
#[bench::n(sorted_ids(1000))]
#[bench::n4(sorted_ids(4000))]
fn scale_merge(ids: Vec<u64>) -> usize {
    black_box(merge(black_box(&ids), black_box(&ids)))
}

library_benchmark_group!(
    name = parsing;
    benchmarks = parse_object, parse_deeply_nested, scale_parse_keys, scale_parse_colliding_keys
);

library_benchmark_group!(
    name = indexing;
    benchmarks = scale_merge
);

main!(library_benchmark_groups = parsing, indexing);
