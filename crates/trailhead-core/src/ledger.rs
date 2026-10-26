//! The public ledger: an append-only, hash-chained log of every prompt, model response, gate
//! verdict, governor decision and credit movement. Each event's hash covers the previous hash,
//! so editing or deleting any past event breaks every hash after it. Signed checkpoints let
//! outsiders pin the head; see docs/TRANSPARENCY.md.

use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

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

pub fn compute_hash(
    prev_hash: &str,
    seq: i64,
    ts: &DateTime<Utc>,
    kind: &str,
    intent_id: Option<i64>,
    actor: &str,
    payload: &Value,
) -> String {
    let body = serde_json::json!({
        "seq": seq,
        "ts": ts_string(ts),
        "kind": kind,
        "intent_id": intent_id,
        "actor": actor,
        "payload": canonical(payload),
    });
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
        let expect = compute_hash(
            &prev,
            e.seq,
            &e.ts,
            &e.kind,
            e.intent_id,
            &e.actor,
            &e.payload,
        );
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
}
