//! chunking.rs -- Rust port of otp_chunking.py.
//!
//! Operates on signed ciphertext from transport.rs -- not secret. Per-chunk
//! hash (unkeyed) gives fail-fast corruption/injection detection; it does
//! NOT provide sender authentication -- that guarantee is entirely the
//! Ed25519 signature, verified after assemble() via transport::verify_and_unwrap.
//!
//! The total_chunks bound exists purely for DoS resistance: a forged
//! header claiming an enormous total_chunks must not cause unbounded
//! allocation. The bound check happens BEFORE any Vec sized by total is
//! allocated.

use crate::sodium_ffi::unkeyed_hash;

pub const SESSION_ID_LEN: usize = 16;
const SEQ_LEN: usize = 4;
const TOTAL_LEN: usize = 4;
const PAYLOAD_LEN_LEN: usize = 4;
pub const HEADER_LEN: usize = SESSION_ID_LEN + SEQ_LEN + TOTAL_LEN + PAYLOAD_LEN_LEN; // 28
pub const CHUNK_HASH_LEN: usize = 32;
pub const DEFAULT_MAX_TOTAL_CHUNKS: u32 = 100_000;

const CHUNK_HASH_PERSON: &[u8; 16] = b"otp_chunk_hash__";

#[derive(Debug)]
pub enum ChunkError {
    Corrupt(String),
    SequenceViolation(String),
}

fn chunk_hash(header_and_payload: &[u8]) -> [u8; CHUNK_HASH_LEN] {
    unkeyed_hash(header_and_payload, CHUNK_HASH_PERSON)
}

/// Splits `payload` (signed ciphertext, not secret) into chunks of
/// header || payload_slice || hash. Ownership note: this necessarily
/// copies from `payload` into each chunk's own Vec<u8> -- chunks must
/// outlive the caller's borrow once handed to a transport layer, and
/// since this is ciphertext (not plaintext), the copy costs nothing
/// confidentiality-wise, same reasoning as the Python port.
pub fn encode_chunks(payload: &[u8], chunk_payload_size: usize, session_id: Option<[u8; SESSION_ID_LEN]>) -> Vec<Vec<u8>> {
    let session_id = session_id.unwrap_or_else(random_session_id);
    let total_chunks = ((payload.len() + chunk_payload_size - 1) / chunk_payload_size).max(1) as u32;

    let mut chunks = Vec::with_capacity(total_chunks as usize);
    for seq in 0..total_chunks {
        let start = seq as usize * chunk_payload_size;
        let end = (start + chunk_payload_size).min(payload.len());
        let chunk_payload = &payload[start..end];

        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(&session_id);
        header.extend_from_slice(&seq.to_be_bytes());
        header.extend_from_slice(&total_chunks.to_be_bytes());
        header.extend_from_slice(&(chunk_payload.len() as u32).to_be_bytes());

        let mut header_and_payload = header.clone();
        header_and_payload.extend_from_slice(chunk_payload);
        let h = chunk_hash(&header_and_payload);

        let mut chunk = header_and_payload;
        chunk.extend_from_slice(&h);
        chunks.push(chunk);
    }
    chunks
}

fn random_session_id() -> [u8; SESSION_ID_LEN] {
    use std::io::Read;
    let mut id = [0u8; SESSION_ID_LEN];
    std::fs::File::open("/dev/urandom").unwrap().read_exact(&mut id).unwrap();
    id
}

/// Strict in-order, single-session chunk reassembly with fail-fast
/// corruption/injection detection. Does NOT itself authenticate the
/// sender -- see module docstring.
pub struct ChunkReassembler {
    max_total_chunks: u32,
    session_id: Option<[u8; SESSION_ID_LEN]>,
    total_chunks: Option<u32>,
    received: Vec<Option<Vec<u8>>>,
    pub next_expected_seq: u32,
}

impl ChunkReassembler {
    pub fn new(max_total_chunks: u32) -> Self {
        ChunkReassembler {
            max_total_chunks,
            session_id: None,
            total_chunks: None,
            received: Vec::new(),
            next_expected_seq: 0,
        }
    }

    pub fn default() -> Self {
        Self::new(DEFAULT_MAX_TOTAL_CHUNKS)
    }

    /// Returns Ok(true) once the full sequence has been received.
    pub fn ingest(&mut self, raw_chunk: &[u8]) -> Result<bool, ChunkError> {
        if raw_chunk.len() < HEADER_LEN + CHUNK_HASH_LEN {
            return Err(ChunkError::Corrupt("chunk shorter than minimum header+hash length".into()));
        }

        let session_id: [u8; SESSION_ID_LEN] = raw_chunk[0..SESSION_ID_LEN].try_into().unwrap();
        let mut off = SESSION_ID_LEN;
        let seq = u32::from_be_bytes(raw_chunk[off..off+SEQ_LEN].try_into().unwrap()); off += SEQ_LEN;
        let total = u32::from_be_bytes(raw_chunk[off..off+TOTAL_LEN].try_into().unwrap()); off += TOTAL_LEN;
        let payload_len = u32::from_be_bytes(raw_chunk[off..off+PAYLOAD_LEN_LEN].try_into().unwrap()) as usize; off += PAYLOAD_LEN_LEN;

        let expected_total_len = HEADER_LEN + payload_len + CHUNK_HASH_LEN;
        if raw_chunk.len() != expected_total_len {
            return Err(ChunkError::Corrupt(
                "declared payload_len doesn't match actual chunk length".into(),
            ));
        }

        let payload = &raw_chunk[off..off+payload_len];
        let received_hash = &raw_chunk[off+payload_len..off+payload_len+CHUNK_HASH_LEN];
        let header = &raw_chunk[0..HEADER_LEN];

        let mut header_and_payload = Vec::with_capacity(HEADER_LEN + payload_len);
        header_and_payload.extend_from_slice(header);
        header_and_payload.extend_from_slice(payload);
        let expected_hash = chunk_hash(&header_and_payload);

        if !constant_time_eq(&expected_hash, received_hash) {
            return Err(ChunkError::Corrupt("chunk hash mismatch -- corrupted or forged chunk".into()));
        }

        // Bound check happens AFTER hash verification (matching the Python
        // port's actual behavior -- a tampered total_chunks field also
        // invalidates the hash, since the hash covers the whole header),
        // but crucially BEFORE any Vec sized by `total` is allocated.
        if total == 0 || total > self.max_total_chunks {
            return Err(ChunkError::Corrupt(format!(
                "declared total_chunks {} outside sane bound (1..{})", total, self.max_total_chunks
            )));
        }

        match self.session_id {
            None => {
                self.session_id = Some(session_id);
                self.total_chunks = Some(total);
                self.received = vec![None; total as usize]; // safe: bound-checked above
            }
            Some(existing) => {
                if session_id != existing {
                    return Err(ChunkError::SequenceViolation(
                        "session_id mismatch -- possible attempt to stitch chunks from two different transmissions together".into(),
                    ));
                }
                if Some(total) != self.total_chunks {
                    return Err(ChunkError::SequenceViolation("total_chunks changed mid-stream".into()));
                }
            }
        }

        if seq != self.next_expected_seq {
            return Err(ChunkError::SequenceViolation(format!(
                "out-of-order or duplicate/replayed chunk: expected seq {}, got {}",
                self.next_expected_seq, seq
            )));
        }

        self.received[seq as usize] = Some(payload.to_vec());
        self.next_expected_seq += 1;
        Ok(self.next_expected_seq == self.total_chunks.unwrap())
    }

    pub fn assemble(&self) -> Result<Vec<u8>, ChunkError> {
        let total = self.total_chunks.ok_or_else(|| ChunkError::Corrupt("no chunks received".into()))?;
        if self.next_expected_seq != total {
            return Err(ChunkError::Corrupt(format!(
                "incomplete sequence: received {} of {} expected chunks", self.next_expected_seq, total
            )));
        }
        let mut out = Vec::new();
        for i in 0..total as usize {
            out.extend_from_slice(self.received[i].as_ref().unwrap());
        }
        Ok(out)
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff: u8 = 0;
    for i in 0..a.len() { diff |= a[i] ^ b[i]; }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::locked_buffer::LockedBuffer;
    use crate::transport::{generate_box_keypair, generate_sign_keypair, seal_pad, sign_and_wrap, verify_and_unwrap, open_sealed};

    #[test]
    fn full_end_to_end_through_transport() {
        let (box_pk_b, box_sk_b) = generate_box_keypair().unwrap();
        let (sign_pk_a, sign_sk_a) = generate_sign_keypair().unwrap();

        let plaintext: Vec<u8> = (0..=255u8).cycle().take(256).collect();
        let mut pt_buf = LockedBuffer::new(plaintext.len()).unwrap();
        pt_buf.write_at(0, &plaintext).unwrap();
        let ciphertext = seal_pad(&pt_buf, plaintext.len(), box_pk_b.as_slice()).unwrap();
        let signed_ct = sign_and_wrap(&ciphertext, &sign_sk_a).unwrap();

        let chunks = encode_chunks(&signed_ct, 64, None);
        assert!(chunks.len() > 1, "test needs multiple chunks to be meaningful");

        let mut reassembler = ChunkReassembler::default();
        let mut complete = false;
        for c in &chunks {
            complete = reassembler.ingest(c).unwrap();
        }
        assert!(complete);
        let reassembled = reassembler.assemble().unwrap();
        assert_eq!(reassembled, signed_ct);

        let recovered_ct = verify_and_unwrap(&reassembled, sign_pk_a.as_slice()).unwrap();
        let mut out_buf = LockedBuffer::new(plaintext.len()).unwrap();
        let n = open_sealed(&recovered_ct, &box_pk_b, &box_sk_b, &mut out_buf).unwrap();
        assert_eq!(&out_buf.as_slice()[..n], &plaintext[..]);
    }

    fn sample_chunks() -> Vec<Vec<u8>> {
        let payload: Vec<u8> = (0..200u8).collect();
        encode_chunks(&payload, 40, Some([9u8; 16]))
    }

    #[test]
    fn truncation_detected() {
        let chunks = sample_chunks();
        let mut r = ChunkReassembler::default();
        for c in &chunks[..chunks.len() - 1] {
            let complete = r.ingest(c).unwrap();
            assert!(!complete);
        }
        match r.assemble() {
            Err(ChunkError::Corrupt(_)) => {}
            other => panic!("expected incomplete-sequence error, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn out_of_order_rejected_immediately() {
        let chunks = sample_chunks();
        let mut r = ChunkReassembler::default();
        r.ingest(&chunks[0]).unwrap();
        match r.ingest(&chunks[2]) {
            Err(ChunkError::SequenceViolation(_)) => {}
            other => panic!("expected SequenceViolation, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn session_stitching_rejected() {
        let chunks = sample_chunks();
        let other_payload = b"UNRELATED SECOND MESSAGE".to_vec();
        let other_chunks = encode_chunks(&other_payload, 64, Some([0xEEu8; 16]));

        let mut r = ChunkReassembler::default();
        r.ingest(&chunks[0]).unwrap();
        match r.ingest(&other_chunks[0]) {
            Err(ChunkError::SequenceViolation(_)) => {}
            other => panic!("expected SequenceViolation (stitching), got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn corrupted_payload_rejected() {
        let chunks = sample_chunks();
        let mut tampered = chunks[1].clone();
        tampered[HEADER_LEN + 2] ^= 0xFF;
        let mut r = ChunkReassembler::default();
        r.ingest(&chunks[0]).unwrap();
        match r.ingest(&tampered) {
            Err(ChunkError::Corrupt(_)) => {}
            other => panic!("expected Corrupt (hash mismatch), got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn duplicate_replay_rejected() {
        let chunks = sample_chunks();
        let mut r = ChunkReassembler::default();
        r.ingest(&chunks[0]).unwrap();
        r.ingest(&chunks[1]).unwrap();
        match r.ingest(&chunks[0]) {
            Err(ChunkError::SequenceViolation(_)) => {}
            other => panic!("expected SequenceViolation (replay), got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn dos_bound_isolated_from_hash_check() {
        // Build a chunk with a forged total_chunks value FROM SCRATCH, with
        // a correctly-recomputed hash over the forged header -- isolates
        // whether the total_chunks bound check itself catches it, same
        // fix applied to the Python port's originally-wrong version of
        // this test (which accidentally passed via hash-mismatch instead).
        let chunks = sample_chunks();
        let c0 = &chunks[0];
        let payload0 = &c0[HEADER_LEN..c0.len() - CHUNK_HASH_LEN];

        let mut forged_header = Vec::with_capacity(HEADER_LEN);
        forged_header.extend_from_slice(&c0[0..SESSION_ID_LEN]);
        forged_header.extend_from_slice(&0u32.to_be_bytes());
        forged_header.extend_from_slice(&4_000_000_000u32.to_be_bytes());
        forged_header.extend_from_slice(&(payload0.len() as u32).to_be_bytes());

        let mut header_and_payload = forged_header.clone();
        header_and_payload.extend_from_slice(payload0);
        let forged_hash = chunk_hash(&header_and_payload);

        let mut forged_chunk = header_and_payload;
        forged_chunk.extend_from_slice(&forged_hash);

        let mut r = ChunkReassembler::default();
        match r.ingest(&forged_chunk) {
            Err(ChunkError::Corrupt(msg)) => {
                assert!(msg.contains("outside sane bound"), "rejected for the wrong reason: {}", msg);
            }
            other => panic!("expected rejection by the bound check specifically, got {:?}", other.map(|_| ())),
        }
    }
}
