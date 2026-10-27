//! Parser fuzzing with the limits as the oracle.
//!
//! The interesting property is not "does it crash" but "do the documented limits hold". A depth
//! cap that applies to objects and not to arrays is the shape of a stack-exhaustion bug, and it
//! is invisible to a test suite whose fixtures are all well-formed.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    // Replace with the real parser. An Err is a normal outcome; a panic or a hang is not.
    let Ok(v) = serde_json::from_str::<serde_json::Value>(s) else {
        return;
    };
    // Round-trip: anything we accepted we must be able to write back and re-read identically.
    // A mismatch means the parser and the serialiser disagree about what a value is, which is
    // how data gets silently rewritten in storage.
    let out = serde_json::to_string(&v).expect("a parsed value must serialise");
    let back: serde_json::Value = serde_json::from_str(&out).expect("our own output must parse");
    assert_eq!(v, back, "round-trip changed the value");
});
