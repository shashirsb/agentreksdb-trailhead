//! Synthetic fixture for gates/checks/invariants.py. NOT REAL CODE.

/// VIOLATION unsafe.unchecked-call-allowlist: an unchecked call from a plain utility module.
pub fn label_of(buf: &[u8]) -> &str {
    unsafe { std::str::from_utf8_unchecked(buf) }
}

/// VIOLATION unsafe.unchecked-call-allowlist: a second unchecked escape hatch.
pub fn first_byte(buf: &[u8]) -> u8 {
    unsafe { *buf.get_unchecked(0) }
}

/// Not a call: this is the definition of an unchecked helper, which the checker ignores.
pub unsafe fn shrink_unchecked(v: &mut Vec<u8>, n: usize) {
    v.set_len(n);
}
