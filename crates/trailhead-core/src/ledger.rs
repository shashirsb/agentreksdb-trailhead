//! The public ledger: an append-only, hash-chained log of every prompt, model response, gate
//! verdict, governor decision and credit movement. Each event's hash covers the previous hash,
//! so editing or deleting any past event breaks every hash after it. Signed checkpoints let
//! outsiders pin the head; see docs/TRANSPARENCY.md.
//!
//! # Why there are two hash versions
//!
//! `docs/TRANSPARENCY.md` promises that a payload can be removed — a leaked secret, personal
//! data somebody is entitled to have erased, illegal content — and that "the chain still
//! verifies". Under **v1** that promise could not be kept: the hash was taken over the payload
//! bytes themselves, so removing a payload broke that event's hash and every hash after it.
//! The policy said one thing and the arithmetic did another.
//!
//! **v2** fixes it the way Certificate Transparency and the EDPB's blockchain guidance both
//! suggest: the chain commits to a *salted hash* of the payload rather than to the payload.
//! Removing a payload then deletes the payload and its salt and leaves the commitment, so the
//! chain still verifies for everyone while the content is genuinely gone.
//!
//! The salt matters. Many payloads are short and predictable — a verdict, a decision, a credit
//! amount — and an unsalted hash of a small value is reversible by simply hashing the
//! candidates. A per-event random salt makes the commitment reveal nothing once it is deleted.
//!
//! Old events are **not** rehashed. Rewriting history to adopt a better scheme would invalidate
//! every checkpoint anyone has pinned, which is precisely the thing this ledger exists to make
//! impossible. Each event carries its own version and is verified under the rules it was
//! written with, so a verifier walking from genesis to head checks a v1 prefix and a v2 suffix
//! and accepts both.

use std::fmt::Write as _;

use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// The hash scheme an event was written under. Stored per event, never changed afterwards.
pub const HASH_V1_INLINE_PAYLOAD: i16 = 1;
/// The chain commits to `payload_commit`; the payload is removable. See the module docs.
pub const HASH_V2_SALTED_COMMIT: i16 = 2;

/// The payload every removed event is left showing. The commitment stays in the chain, so the
/// event still proves *that something was recorded at this point*, and the governor decision
/// that removed it is itself an event anyone can read.
pub fn tombstone(reason: &str) -> Value {
    serde_json::json!({ "removed": true, "reason": reason })
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Event {
    pub seq: i64,
    pub ts: DateTime<Utc>,
    pub kind: String,
    pub intent_id: Option<i64>,
    pub actor: String,
    pub payload: Value,
    pub prev_hash: String,
    pub hash: String,
    /// `1` for events written before removable payloads existed. Absent in older JSON, which
    /// deserialises as v1 — exactly what such an event is.
    #[serde(default = "default_hash_version")]
    pub hash_version: i16,
    /// v2 only: `sha256(salt ++ canonical(payload))`, the value the chain actually commits to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_commit: Option<String>,
    /// v2 only: the per-event random salt, hex. Published while the payload is, deleted when
    /// the payload is removed — which is what stops a short payload being recovered by
    /// hashing guesses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_salt: Option<String>,
}

fn default_hash_version() -> i16 {
    HASH_V1_INLINE_PAYLOAD
}

/// `sha256(salt ++ canonical(payload))`: what a v2 chain commits to in place of the payload.
pub fn payload_commit(salt_hex: &str, payload: &Value) -> String {
    let mut h = Sha256::new();
    h.update(salt_hex.as_bytes());
    h.update(b"\n");
    h.update(
        serde_json::to_string(&canonical(payload))
            .expect("json")
            .as_bytes(),
    );
    hex::encode(h.finalize())
}

/// A fresh 32-byte salt, hex encoded.
pub fn new_salt() -> String {
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    let mut s = String::with_capacity(64);
    for byte in b {
        let _ = write!(s, "{byte:02x}");
    }
    s
}

/// Recursively sort object keys so hashing never depends on map order.
pub fn canonical(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for k in keys {
                out.insert(k.clone(), canonical(&m[k]));
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

/// Timestamps are hashed at microsecond precision, which is what Postgres stores.
pub fn ts_string(ts: &DateTime<Utc>) -> String {
    ts.to_rfc3339_opts(SecondsFormat::Micros, true)
}

/// The v1 hash: the payload is hashed inline, so the payload can never be removed.
pub fn compute_hash(
    prev_hash: &str,
    seq: i64,
    ts: &DateTime<Utc>,
    kind: &str,
    intent_id: Option<i64>,
    actor: &str,
    payload: &Value,
) -> String {
    compute_hash_body(
        prev_hash,
        serde_json::json!({
            "seq": seq,
            "ts": ts_string(ts),
            "kind": kind,
            "intent_id": intent_id,
            "actor": actor,
            "payload": canonical(payload),
        }),
    )
}

/// The v2 hash: identical except that it commits to `payload_commit` instead of the payload.
/// The field is named differently from v1's `payload` so the two bodies can never collide: a
/// v1 event and a v2 event cannot be made to hash the same by any choice of contents.
pub fn compute_hash_v2(
    prev_hash: &str,
    seq: i64,
    ts: &DateTime<Utc>,
    kind: &str,
    intent_id: Option<i64>,
    actor: &str,
    commit: &str,
) -> String {
    compute_hash_body(
        prev_hash,
        serde_json::json!({
            "seq": seq,
            "ts": ts_string(ts),
            "kind": kind,
            "intent_id": intent_id,
            "actor": actor,
            "payload_commit": commit,
        }),
    )
}

fn compute_hash_body(prev_hash: &str, body: Value) -> String {
    let mut h = Sha256::new();
    h.update(prev_hash.as_bytes());
    h.update(b"\n");
    h.update(
        serde_json::to_string(&canonical(&body))
            .expect("json")
            .as_bytes(),
    );
    hex::encode(h.finalize())
}

/// Truncate a timestamp to microseconds so the value we hash equals the value Postgres returns.
pub fn trunc_micros(ts: DateTime<Utc>) -> DateTime<Utc> {
    DateTime::from_timestamp_micros(ts.timestamp_micros()).expect("valid timestamp")
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ChainReport {
    pub ok: bool,
    pub checked: usize,
    pub head: String,
    pub first_bad_seq: Option<i64>,
}

/// Verify a contiguous run of events. `prev` is the hash before the first event (GENESIS at seq 1).
pub fn verify(prev: &str, events: &[Event]) -> ChainReport {
    let mut prev = prev.to_string();
    for (i, e) in events.iter().enumerate() {
        let expect = match e.hash_version {
            HASH_V2_SALTED_COMMIT => {
                let Some(commit) = e.payload_commit.as_deref() else {
                    // A v2 event with no commitment commits to nothing and cannot be checked.
                    return ChainReport {
                        ok: false,
                        checked: i,
                        head: prev,
                        first_bad_seq: Some(e.seq),
                    };
                };
                // While the salt is published, the commitment must match the payload on show:
                // this is what stops a payload being swapped for a more flattering one after
                // the fact. Once the salt is deleted the payload has been removed, and only
                // the chain itself is still checkable — which is the whole point of v2.
                if let Some(salt) = e.payload_salt.as_deref() {
                    if payload_commit(salt, &e.payload) != commit {
                        return ChainReport {
                            ok: false,
                            checked: i,
                            head: prev,
                            first_bad_seq: Some(e.seq),
                        };
                    }
                }
                compute_hash_v2(&prev, e.seq, &e.ts, &e.kind, e.intent_id, &e.actor, commit)
            }
            _ => compute_hash(
                &prev,
                e.seq,
                &e.ts,
                &e.kind,
                e.intent_id,
                &e.actor,
                &e.payload,
            ),
        };
        if e.prev_hash != prev || e.hash != expect {
            return ChainReport {
                ok: false,
                checked: i,
                head: prev,
                first_bad_seq: Some(e.seq),
            };
        }
        prev = e.hash.clone();
    }
    ChainReport {
        ok: true,
        checked: events.len(),
        head: prev,
        first_bad_seq: None,
    }
}

pub fn checkpoint_message(seq: i64, head: &str) -> Vec<u8> {
    format!("trailhead-ledger-checkpoint\nseq={seq}\nhead={head}\n").into_bytes()
}

pub fn sign_checkpoint(key: &SigningKey, seq: i64, head: &str) -> String {
    hex::encode(key.sign(&checkpoint_message(seq, head)).to_bytes())
}

pub fn verify_checkpoint(public_key_hex: &str, seq: i64, head: &str, sig_hex: &str) -> bool {
    let Ok(pk) = hex::decode(public_key_hex) else {
        return false;
    };
    let Ok(pk): Result<[u8; 32], _> = pk.try_into() else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    let Ok(sig) = hex::decode(sig_hex) else {
        return false;
    };
    let Ok(sig): Result<[u8; 64], _> = sig.try_into() else {
        return false;
    };
    vk.verify(&checkpoint_message(seq, head), &Signature::from_bytes(&sig))
        .is_ok()
}

/// Parse a 32-byte hex seed, or generate a fresh key if none is configured.
pub fn signing_key(seed_hex: Option<&str>) -> anyhow::Result<SigningKey> {
    match seed_hex {
        Some(s) => {
            let b: [u8; 32] = hex::decode(s.trim())?
                .try_into()
                .map_err(|_| anyhow::anyhow!("ledger key must be 32 bytes of hex"))?;
            Ok(SigningKey::from_bytes(&b))
        }
        None => Ok(SigningKey::generate(&mut rand::rngs::OsRng)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn chain(n: i64) -> Vec<Event> {
        let mut prev = GENESIS.to_string();
        let mut out = Vec::new();
        for seq in 1..=n {
            let ts = trunc_micros(Utc::now());
            let payload = json!({"b": seq, "a": {"z": 1, "y": [2, 3]}});
            let hash = compute_hash(&prev, seq, &ts, "prompt", Some(7), "backend", &payload);
            out.push(Event {
                seq,
                ts,
                kind: "prompt".into(),
                intent_id: Some(7),
                actor: "backend".into(),
                payload,
                prev_hash: prev.clone(),
                hash: hash.clone(),
                hash_version: HASH_V1_INLINE_PAYLOAD,
                payload_commit: None,
                payload_salt: None,
            });
            prev = hash;
        }
        out
    }

    #[test]
    fn intact_chain_verifies() {
        let c = chain(5);
        let r = verify(GENESIS, &c);
        assert!(r.ok);
        assert_eq!(r.head, c[4].hash);
    }

    #[test]
    fn tampering_is_detected_at_the_edited_event() {
        let mut c = chain(5);
        c[2].payload = json!({"b": 999});
        let r = verify(GENESIS, &c);
        assert!(!r.ok);
        assert_eq!(r.first_bad_seq, Some(3));
    }

    #[test]
    fn deletion_is_detected() {
        let mut c = chain(5);
        c.remove(1);
        assert_eq!(verify(GENESIS, &c).first_bad_seq, Some(3));
    }

    #[test]
    fn key_order_does_not_change_the_hash() {
        let ts = trunc_micros(Utc::now());
        let a = compute_hash(GENESIS, 1, &ts, "k", None, "x", &json!({"a": 1, "b": 2}));
        let b = compute_hash(GENESIS, 1, &ts, "k", None, "x", &json!({"b": 2, "a": 1}));
        assert_eq!(a, b);
    }

    #[test]
    fn checkpoints_sign_and_verify() {
        let k = signing_key(None).unwrap();
        let pk = hex::encode(k.verifying_key().to_bytes());
        let sig = sign_checkpoint(&k, 42, "abc");
        assert!(verify_checkpoint(&pk, 42, "abc", &sig));
        assert!(!verify_checkpoint(&pk, 43, "abc", &sig));
    }

    // ---------- v2: removable payloads ----------

    /// Build a v2 event chained onto `prev`.
    fn v2_event(seq: i64, prev: &str, payload: Value) -> Event {
        let ts = trunc_micros(Utc::now());
        let salt = new_salt();
        let commit = payload_commit(&salt, &payload);
        let hash = compute_hash_v2(prev, seq, &ts, "test.kind", Some(7), "backend", &commit);
        Event {
            seq,
            ts,
            kind: "test.kind".into(),
            intent_id: Some(7),
            actor: "backend".into(),
            payload,
            prev_hash: prev.into(),
            hash,
            hash_version: HASH_V2_SALTED_COMMIT,
            payload_commit: Some(commit),
            payload_salt: Some(salt),
        }
    }

    #[test]
    fn a_v2_chain_verifies() {
        let a = v2_event(1, GENESIS, serde_json::json!({"secret": "hunter2"}));
        let b = v2_event(2, &a.hash, serde_json::json!({"x": 1}));
        assert!(verify(GENESIS, &[a, b]).ok);
    }

    /// The promise docs/TRANSPARENCY.md makes, and the reason v2 exists: a payload can be
    /// removed and every later hash still checks out for everyone else.
    #[test]
    fn removing_a_v2_payload_leaves_the_chain_intact() {
        let a = v2_event(
            1,
            GENESIS,
            serde_json::json!({"email": "someone@example.com"}),
        );
        let b = v2_event(2, &a.hash, serde_json::json!({"x": 1}));
        let mut removed = a.clone();
        removed.payload = tombstone("erasure request");
        removed.payload_salt = None;

        let r = verify(GENESIS, &[removed, b.clone()]);
        assert!(r.ok, "chain broke after a removal: {r:?}");
        assert_eq!(r.head, b.hash);
    }

    /// The same removal under v1 breaks the chain. This is the bug v2 was written to fix, and
    /// the test exists so nobody "simplifies" v2 back into v1.
    #[test]
    fn removing_a_v1_payload_breaks_the_chain() {
        let ts = trunc_micros(Utc::now());
        let payload = serde_json::json!({"email": "someone@example.com"});
        let hash = compute_hash(GENESIS, 1, &ts, "test.kind", Some(7), "backend", &payload);
        let mut e = Event {
            seq: 1,
            ts,
            kind: "test.kind".into(),
            intent_id: Some(7),
            actor: "backend".into(),
            payload,
            prev_hash: GENESIS.into(),
            hash,
            hash_version: HASH_V1_INLINE_PAYLOAD,
            payload_commit: None,
            payload_salt: None,
        };
        assert!(verify(GENESIS, &[e.clone()]).ok);
        e.payload = tombstone("erasure request");
        assert!(!verify(GENESIS, &[e]).ok);
    }

    /// While the salt is published, the payload is bound to the commitment: swapping a payload
    /// for a more flattering one must fail even though the hash chain itself is untouched.
    #[test]
    fn a_swapped_payload_is_caught_while_the_salt_is_published() {
        let mut a = v2_event(1, GENESIS, serde_json::json!({"verdict": "block"}));
        a.payload = serde_json::json!({"verdict": "pass"});
        let r = verify(GENESIS, &[a]);
        assert!(!r.ok);
        assert_eq!(r.first_bad_seq, Some(1));
    }

    /// A v2 event with no commitment commits to nothing; it must not be accepted.
    #[test]
    fn a_v2_event_without_a_commitment_is_rejected() {
        let mut a = v2_event(1, GENESIS, serde_json::json!({"x": 1}));
        a.payload_commit = None;
        assert!(!verify(GENESIS, &[a]).ok);
    }

    /// History is not rehashed, so a real ledger is a v1 prefix followed by a v2 suffix.
    #[test]
    fn a_mixed_v1_then_v2_chain_verifies() {
        let ts = trunc_micros(Utc::now());
        let p1 = serde_json::json!({"old": true});
        let h1 = compute_hash(GENESIS, 1, &ts, "old.kind", None, "backend", &p1);
        let old = Event {
            seq: 1,
            ts,
            kind: "old.kind".into(),
            intent_id: None,
            actor: "backend".into(),
            payload: p1,
            prev_hash: GENESIS.into(),
            hash: h1.clone(),
            hash_version: HASH_V1_INLINE_PAYLOAD,
            payload_commit: None,
            payload_salt: None,
        };
        let new = v2_event(2, &h1, serde_json::json!({"new": true}));
        assert!(verify(GENESIS, &[old, new]).ok);
    }

    /// An event stored before versioning existed has no `hash_version` field at all.
    #[test]
    fn json_without_a_version_field_reads_as_v1() {
        let ts = trunc_micros(Utc::now());
        let p = serde_json::json!({"a": 1});
        let h = compute_hash(GENESIS, 1, &ts, "k", None, "backend", &p);
        let raw = serde_json::json!({
            "seq": 1, "ts": ts, "kind": "k", "intent_id": null, "actor": "backend",
            "payload": p, "prev_hash": GENESIS, "hash": h,
        });
        let e: Event = serde_json::from_value(raw).expect("parses");
        assert_eq!(e.hash_version, HASH_V1_INLINE_PAYLOAD);
        assert!(verify(GENESIS, &[e]).ok);
    }

    #[test]
    fn a_salt_is_unique_and_full_length() {
        let a = new_salt();
        let b = new_salt();
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// The two bodies are shaped differently on purpose, so no v1 event can be replayed as a
    /// v2 event (or the reverse) by choosing its contents.
    #[test]
    fn the_two_versions_cannot_collide() {
        let ts = trunc_micros(Utc::now());
        let commit = "ab".repeat(32);
        let as_v2 = compute_hash_v2(GENESIS, 1, &ts, "k", None, "a", &commit);
        let as_v1 = compute_hash(
            GENESIS,
            1,
            &ts,
            "k",
            None,
            "a",
            &serde_json::json!({ "payload_commit": commit }),
        );
        assert_ne!(as_v1, as_v2);
    }
}
