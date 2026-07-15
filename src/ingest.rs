//! ingest.rs -- Rust port of otp_ingest.py's ingestion bridge.
//!
//! Bridges a completed ChunkReassembler through Ed25519 signature
//! verification and sealed-box decryption DIRECTLY into a PadStore's own
//! locked buffer (via the RawWriteTarget generic on open_sealed) -- no
//! intermediate unprotected plaintext pad object anywhere in the path.
//!
//! Fail-shut sequencing: `store` must already be constructed with
//! defer_fill=true by the caller. finalize_fill() -- the single point at
//! which a journal file can first be created -- is only reached after
//! reassembly, signature verification, decryption, AND the size check all
//! succeed. Any failure before that point explicitly clears the store's
//! buffer (undoing any partial/garbage bytes a failed decrypt attempt may
//! have left behind) and returns before finalize_fill() is ever called --
//! so no journal is ever written for a store whose material wasn't fully
//! verified.

use crate::chunking::{ChunkError, ChunkReassembler};
use crate::locked_buffer::LockedBuffer;
use crate::pad_store::{PadStore, PadStoreError};
use crate::transport::{open_sealed, verify_and_unwrap, TransportError};

#[derive(Debug)]
pub enum IngestError {
    Reassembly(ChunkError),
    Signature,
    Decrypt(TransportError),
    SizeMismatch { expected: usize, actual: usize },
    Finalize(PadStoreError),
}

/// `store` must be constructed with defer_fill=true before calling this.
/// On success, store is fully finalized and usable. On any failure, store
/// has been cleared and no journal file exists for it.
pub fn ingest_assembled_payload(
    reassembler: &ChunkReassembler,
    sender_verify_pk: &[u8],
    recipient_box_pk: &LockedBuffer,
    recipient_box_sk: &LockedBuffer,
    store: &mut PadStore,
) -> Result<(), IngestError> {
    let signed_ciphertext = reassembler.assemble().map_err(IngestError::Reassembly)?;

    let ciphertext = verify_and_unwrap(&signed_ciphertext, sender_verify_pk)
        .map_err(|_e| IngestError::Signature)?;

    let expected_size = store.size();
    let n = match open_sealed(&ciphertext, recipient_box_pk, recipient_box_sk, store) {
        Ok(n) => n,
        Err(e) => {
            store.clear();
            return Err(IngestError::Decrypt(e));
        }
    };

    if n != expected_size {
        store.clear();
        return Err(IngestError::SizeMismatch { expected: expected_size, actual: n });
    }

    store.finalize_fill().map_err(IngestError::Finalize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunking::encode_chunks;
    use crate::pad_store::PadStore;
    use crate::transport::{generate_box_keypair, generate_sign_keypair, seal_pad, sign_and_wrap};
    use std::fs;

    fn fresh_journal(name: &str) -> String {
        let p = format!("ingest_test_{}.bin", name);
        let _ = fs::remove_file(&p);
        p
    }

    fn build_valid_chunks(box_pk_b: &[u8], sign_sk_a: &LockedBuffer, plaintext: &[u8]) -> Vec<Vec<u8>> {
        let mut pt_buf = LockedBuffer::new(plaintext.len()).unwrap();
        pt_buf.write_at(0, plaintext).unwrap();
        let ciphertext = seal_pad(&pt_buf, plaintext.len(), box_pk_b).unwrap();
        let signed_ct = sign_and_wrap(&ciphertext, sign_sk_a).unwrap();
        encode_chunks(&signed_ct, 40, None)
    }

    #[test]
    fn happy_path_produces_usable_store_with_correct_material() {
        let (box_pk_b, box_sk_b) = generate_box_keypair().unwrap();
        let (sign_pk_a, sign_sk_a) = generate_sign_keypair().unwrap();
        let plaintext: Vec<u8> = (0..128u8).cycle().take(128).collect();

        let chunks = build_valid_chunks(box_pk_b.as_slice(), &sign_sk_a, &plaintext);
        let mut reassembler = ChunkReassembler::default();
        for c in &chunks { reassembler.ingest(c).unwrap(); }

        let journal = fresh_journal("happy");
        let mut store = PadStore::new(plaintext.len(), &journal, None, true).unwrap();

        ingest_assembled_payload(&reassembler, sign_pk_a.as_slice(), &box_pk_b, &box_sk_b, &mut store).unwrap();

        assert!(std::path::Path::new(&journal).exists(), "journal should exist after successful ingestion");
        let (off, bytes) = store.reserve(20).unwrap();
        assert_eq!(off, 0);
        assert_eq!(bytes, plaintext[0..20]);
        store.clear();
        let _ = fs::remove_file(&journal);
    }

    #[test]
    fn incomplete_reassembly_aborts_with_zero_journal() {
        let (box_pk_b, box_sk_b) = generate_box_keypair().unwrap();
        let (sign_pk_a, sign_sk_a) = generate_sign_keypair().unwrap();
        let plaintext = vec![1u8; 128];
        let chunks = build_valid_chunks(box_pk_b.as_slice(), &sign_sk_a, &plaintext);

        let mut reassembler = ChunkReassembler::default();
        for c in &chunks[..chunks.len() - 1] { reassembler.ingest(c).unwrap(); } // drop last chunk

        let journal = fresh_journal("incomplete");
        let mut store = PadStore::new(plaintext.len(), &journal, None, true).unwrap();

        match ingest_assembled_payload(&reassembler, sign_pk_a.as_slice(), &box_pk_b, &box_sk_b, &mut store) {
            Err(IngestError::Reassembly(_)) => {}
            other => panic!("expected Reassembly error, got {:?}", other),
        }
        assert!(!std::path::Path::new(&journal).exists(), "journal must NOT exist after incomplete-reassembly failure");
    }

    #[test]
    fn bad_signature_aborts_with_zero_journal() {
        let (box_pk_b, box_sk_b) = generate_box_keypair().unwrap();
        let (_sign_pk_a, sign_sk_a) = generate_sign_keypair().unwrap();
        let (sign_pk_x, _sign_sk_x) = generate_sign_keypair().unwrap(); // unrelated identity
        let plaintext = vec![2u8; 128];
        let chunks = build_valid_chunks(box_pk_b.as_slice(), &sign_sk_a, &plaintext);

        let mut reassembler = ChunkReassembler::default();
        for c in &chunks { reassembler.ingest(c).unwrap(); }

        let journal = fresh_journal("badsig");
        let mut store = PadStore::new(plaintext.len(), &journal, None, true).unwrap();

        match ingest_assembled_payload(&reassembler, sign_pk_x.as_slice(), &box_pk_b, &box_sk_b, &mut store) {
            Err(IngestError::Signature) => {}
            other => panic!("expected Signature error, got {:?}", other),
        }
        assert!(!std::path::Path::new(&journal).exists(), "journal must NOT exist after signature failure");
    }

    #[test]
    fn wrong_recipient_keypair_aborts_with_zero_journal() {
        let (box_pk_b, _box_sk_b) = generate_box_keypair().unwrap();
        let (box_pk_wrong, box_sk_wrong) = generate_box_keypair().unwrap();
        let (sign_pk_a, sign_sk_a) = generate_sign_keypair().unwrap();
        let plaintext = vec![3u8; 128];
        let chunks = build_valid_chunks(box_pk_b.as_slice(), &sign_sk_a, &plaintext);

        let mut reassembler = ChunkReassembler::default();
        for c in &chunks { reassembler.ingest(c).unwrap(); }

        let journal = fresh_journal("badbox");
        let mut store = PadStore::new(plaintext.len(), &journal, None, true).unwrap();

        match ingest_assembled_payload(&reassembler, sign_pk_a.as_slice(), &box_pk_wrong, &box_sk_wrong, &mut store) {
            Err(IngestError::Decrypt(_)) => {}
            other => panic!("expected Decrypt error, got {:?}", other),
        }
        assert!(!std::path::Path::new(&journal).exists(), "journal must NOT exist after decryption failure");
    }

    #[test]
    fn size_mismatch_aborts_with_zero_journal() {
        let (box_pk_b, box_sk_b) = generate_box_keypair().unwrap();
        let (sign_pk_a, sign_sk_a) = generate_sign_keypair().unwrap();
        let plaintext = vec![4u8; 128];
        let chunks = build_valid_chunks(box_pk_b.as_slice(), &sign_sk_a, &plaintext);

        let mut reassembler = ChunkReassembler::default();
        for c in &chunks { reassembler.ingest(c).unwrap(); }

        let journal = fresh_journal("sizemismatch");
        // Deliberately request a DIFFERENT pad_size than what was actually sent.
        let mut store = PadStore::new(plaintext.len() + 10, &journal, None, true).unwrap();

        match ingest_assembled_payload(&reassembler, sign_pk_a.as_slice(), &box_pk_b, &box_sk_b, &mut store) {
            Err(IngestError::SizeMismatch { expected, actual }) => {
                assert_eq!(expected, plaintext.len() + 10);
                assert_eq!(actual, plaintext.len());
            }
            other => panic!("expected SizeMismatch, got {:?}", other),
        }
        assert!(!std::path::Path::new(&journal).exists(), "journal must NOT exist after size-mismatch failure");
    }
}
