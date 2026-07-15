//! export.rs -- Rust port of otp_export.py: sender-side export.
//!
//! reserve_into() -> seal_pad() -> sign_and_wrap() -> encode_chunks().
//! Plaintext never leaves locked memory until it becomes non-secret
//! ciphertext (seal_pad's output). Deliberate property, ported exactly:
//! reserve_into()'s journal write happens BEFORE sealing/signing/chunking,
//! so a crash or lost transmission after that point burns the pad bytes
//! locally rather than risking reuse -- "maybe sent, definitely burned"
//! over "maybe sent, maybe reissued."

use crate::chunking::{encode_chunks, SESSION_ID_LEN};
use crate::locked_buffer::LockedBuffer;
use crate::pad_store::{PadStore, PadStoreError};
use crate::transport::{seal_pad, sign_and_wrap, TransportError};

#[derive(Debug)]
pub enum ExportError {
    Reserve(PadStoreError),
    Seal(TransportError),
    Sign(TransportError),
}

/// Returns (source_offset, chunks) on success. source_offset is metadata
/// only, not security-relevant. If reserve_into() itself fails (e.g.
/// exhaustion), nothing is sealed/signed/chunked and nothing was burned
/// either -- reserve_into() only advances the journal on its own
/// successful path (verified in pad_store.rs's exhaustion_refusal test).
pub fn export_pad_payload(
    pad_store: &mut PadStore,
    n: usize,
    recipient_box_pk: &[u8],
    sender_sign_sk: &LockedBuffer,
    chunk_payload_size: usize,
    session_id: Option<[u8; SESSION_ID_LEN]>,
) -> Result<(usize, Vec<Vec<u8>>), ExportError> {
    let mut plaintext_buf = LockedBuffer::new(n).map_err(|e| ExportError::Reserve(PadStoreError::Locked(e)))?;

    // Atomic, zero-intermediate-heap-copy: journal advances BEFORE this
    // call returns. From this point on, these n pad bytes are burned
    // locally regardless of what happens below.
    let source_offset = pad_store
        .reserve_into(n, plaintext_buf.as_mut_slice())
        .map_err(ExportError::Reserve)?;

    let ciphertext = seal_pad(&plaintext_buf, n, recipient_box_pk).map_err(ExportError::Seal)?;
    plaintext_buf.clear(); // explicit -- ciphertext already produced, nothing lost

    let signed_ciphertext = sign_and_wrap(&ciphertext, sender_sign_sk).map_err(ExportError::Sign)?;

    let chunks = encode_chunks(&signed_ciphertext, chunk_payload_size, session_id);
    Ok((source_offset, chunks))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunking::ChunkReassembler;
    use crate::ingest::ingest_assembled_payload;
    use crate::pad_store::PadStoreError;
    use crate::transport::{generate_box_keypair, generate_sign_keypair};
    use std::fs;
    use std::io::Read;

    fn fresh_journal(name: &str) -> String {
        let p = format!("export_test_{}.bin", name);
        let _ = fs::remove_file(&p);
        p
    }

    fn random_bytes(n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        std::fs::File::open("/dev/urandom").unwrap().read_exact(&mut buf).unwrap();
        buf
    }

    #[test]
    fn full_closed_loop_exact_byte_match() {
        let (box_pk_recipient, box_sk_recipient) = generate_box_keypair().unwrap();
        let (sign_pk_sender, sign_sk_sender) = generate_sign_keypair().unwrap();

        let sender_journal = fresh_journal("closedloop_sender");
        let receiver_journal = fresh_journal("closedloop_receiver");

        let sender_pad_material = random_bytes(256);
        let mut sender_store = PadStore::new(256, &sender_journal, Some(&sender_pad_material), false).unwrap();

        let (src_offset, chunks) = export_pad_payload(
            &mut sender_store, 64, box_pk_recipient.as_slice(), &sign_sk_sender, 40, None,
        ).unwrap();
        assert_eq!(src_offset, 0);
        assert!(chunks.len() > 1);

        let mut reassembler = ChunkReassembler::default();
        for c in &chunks { reassembler.ingest(c).unwrap(); }

        let mut receiver_store = PadStore::new(64, &receiver_journal, None, true).unwrap();
        ingest_assembled_payload(
            &reassembler, sign_pk_sender.as_slice(), &box_pk_recipient, &box_sk_recipient, &mut receiver_store,
        ).unwrap();

        let (_, received_bytes) = receiver_store.reserve(64).unwrap();
        assert_eq!(received_bytes, sender_pad_material[0..64],
                   "receiver's pad material doesn't match what sender actually burned");

        sender_store.clear();
        receiver_store.clear();
        let _ = fs::remove_file(&sender_journal);
        let _ = fs::remove_file(&receiver_journal);
    }

    #[test]
    fn atomic_local_consumption_survives_lost_transmission() {
        let (box_pk_recipient, _box_sk_recipient) = generate_box_keypair().unwrap();
        let (_sign_pk_sender, sign_sk_sender) = generate_sign_keypair().unwrap();

        let journal = fresh_journal("atomic");
        let pad_material = random_bytes(128);
        {
            let mut sender_store = PadStore::new(128, &journal, Some(&pad_material), false).unwrap();
            assert_eq!(sender_store.remaining().unwrap(), 128);

            let (_, chunks) = export_pad_payload(
                &mut sender_store, 30, box_pk_recipient.as_slice(), &sign_sk_sender, 100, None,
            ).unwrap();
            let _ = chunks; // deliberately discarded -- simulating lost transmission

            assert_eq!(sender_store.remaining().unwrap(), 98);
            sender_store.clear();
        }
        // Reload using the same pad_material (journal MAC key derives from pad content).
        let mut reloaded = PadStore::new(128, &journal, Some(&pad_material), false).unwrap();
        assert_eq!(reloaded.remaining().unwrap(), 98,
                   "pad bytes should stay burned even though the chunks were never used");
        reloaded.clear();
        let _ = fs::remove_file(&journal);
    }

    #[test]
    fn exhaustion_fails_before_burning_anything() {
        let (box_pk_recipient, _box_sk_recipient) = generate_box_keypair().unwrap();
        let (_sign_pk_sender, sign_sk_sender) = generate_sign_keypair().unwrap();

        let journal = fresh_journal("exhaust");
        let pad_material = random_bytes(16);
        let mut sender_store = PadStore::new(16, &journal, Some(&pad_material), false).unwrap();

        match export_pad_payload(&mut sender_store, 100, box_pk_recipient.as_slice(), &sign_sk_sender, 40, None) {
            Err(ExportError::Reserve(PadStoreError::Exhausted { requested, remaining })) => {
                assert_eq!(requested, 100);
                assert_eq!(remaining, 16);
            }
            other => panic!("expected Reserve(Exhausted), got {:?}", other),
        }
        assert_eq!(sender_store.remaining().unwrap(), 16, "exhaustion failure must not burn any pad bytes");
        sender_store.clear();
        let _ = fs::remove_file(&journal);
    }

    #[test]
    fn chunk_output_is_transport_ready() {
        let (box_pk_recipient, _box_sk_recipient) = generate_box_keypair().unwrap();
        let (_sign_pk_sender, sign_sk_sender) = generate_sign_keypair().unwrap();

        let journal = fresh_journal("chunks");
        let pad_material = random_bytes(500);
        let mut sender_store = PadStore::new(500, &journal, Some(&pad_material), false).unwrap();

        let (_, chunks) = export_pad_payload(
            &mut sender_store, 300, box_pk_recipient.as_slice(), &sign_sk_sender, 50, None,
        ).unwrap();
        assert!(chunks.len() >= 7);

        let mut r = ChunkReassembler::default();
        let mut completed = false;
        for c in &chunks { completed = r.ingest(c).unwrap(); }
        assert!(completed);

        sender_store.clear();
        let _ = fs::remove_file(&journal);
    }
}
