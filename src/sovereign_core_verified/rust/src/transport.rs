//! transport.rs -- Rust port of otp_transport.py Phase 1 + 1b.
//!
//! Pointer-only for anything touching secret key material or plaintext:
//! keys generated directly into LockedBuffer via raw FFI pointers, seal/
//! sign operate on LockedBuffer.as_slice()/as_mut_ptr_raw() directly.
//! Ciphertext and signed-ciphertext ARE ordinary Vec<u8> -- ported from
//! the same reasoning as the Python side: their confidentiality comes
//! from the algorithm, not from memory locking, since they're the
//! artifacts meant to cross the transport boundary.

use crate::locked_buffer::{LockedBuffer, LockedBufferError};
use crate::sodium_ffi::*;

#[derive(Debug)]
pub enum TransportError {
    Locked(LockedBufferError),
    KeypairGenFailed(&'static str),
    SealFailed,
    SealOpenFailed,
    SignFailed,
    SignatureVerificationFailed,
    InvalidArgs(String),
}

impl From<LockedBufferError> for TransportError {
    fn from(e: LockedBufferError) -> Self { TransportError::Locked(e) }
}

pub fn generate_box_keypair() -> Result<(LockedBuffer, LockedBuffer), TransportError> {
    let mut pk = LockedBuffer::new(box_publickeybytes())?;
    let mut sk = LockedBuffer::new(box_secretkeybytes())?;
    let rc = box_keypair(pk.as_mut_ptr_raw(), sk.as_mut_ptr_raw());
    if rc != 0 {
        pk.clear();
        sk.clear();
        return Err(TransportError::KeypairGenFailed("crypto_box_keypair"));
    }
    Ok((pk, sk))
}

pub fn generate_sign_keypair() -> Result<(LockedBuffer, LockedBuffer), TransportError> {
    let mut pk = LockedBuffer::new(sign_publickeybytes())?;
    let mut sk = LockedBuffer::new(sign_secretkeybytes())?;
    let rc = sign_keypair(pk.as_mut_ptr_raw(), sk.as_mut_ptr_raw());
    if rc != 0 {
        pk.clear();
        sk.clear();
        return Err(TransportError::KeypairGenFailed("crypto_sign_keypair"));
    }
    Ok((pk, sk))
}

/// Seals `plaintext_len` bytes read directly from plaintext_buf's locked
/// memory against recipient_pk. Returns ciphertext as an ordinary Vec --
/// safe, per module docstring.
pub fn seal_pad(plaintext_buf: &LockedBuffer, plaintext_len: usize, recipient_pk: &[u8]) -> Result<Vec<u8>, TransportError> {
    if plaintext_len > plaintext_buf.len() {
        return Err(TransportError::InvalidArgs("plaintext_len exceeds buffer size".into()));
    }
    if recipient_pk.len() != box_publickeybytes() {
        return Err(TransportError::InvalidArgs("recipient_pk wrong length".into()));
    }
    let mut ciphertext = vec![0u8; plaintext_len + box_sealbytes()];
    let rc = box_seal(
        ciphertext.as_mut_ptr(),
        plaintext_buf.as_slice().as_ptr(),
        plaintext_len as u64,
        recipient_pk.as_ptr(),
    );
    if rc != 0 {
        return Err(TransportError::SealFailed);
    }
    Ok(ciphertext)
}

use crate::locked_buffer::RawWriteTarget;

/// Decrypts ciphertext directly into out_buf's locked memory. out_buf can
/// be a plain LockedBuffer OR a PadStore (defer_fill mode) -- generic over
/// RawWriteTarget specifically so the ingestion bridge can decrypt straight
/// into a PadStore's own buffer with zero intermediate copies, mirroring
/// the Python port's duck-typed out_buf parameter. Returns the plaintext
/// length. Never returns partial/garbage data on failure -- caller must
/// check the Result before trusting out_buf at all.
pub fn open_sealed<T: RawWriteTarget>(ciphertext: &[u8], recipient_pk: &LockedBuffer, recipient_sk: &LockedBuffer, out_buf: &mut T) -> Result<usize, TransportError> {
    let seal_overhead = box_sealbytes();
    if ciphertext.len() < seal_overhead {
        return Err(TransportError::InvalidArgs("ciphertext shorter than seal overhead".into()));
    }
    let pt_len = ciphertext.len() - seal_overhead;
    if pt_len > out_buf.len() {
        return Err(TransportError::InvalidArgs("decrypted plaintext would exceed out_buf size".into()));
    }
    let rc = box_seal_open(
        out_buf.as_mut_ptr_raw(),
        ciphertext.as_ptr(),
        ciphertext.len() as u64,
        recipient_pk.as_slice().as_ptr(),
        recipient_sk.as_slice().as_ptr(),
    );
    if rc != 0 {
        return Err(TransportError::SealOpenFailed);
    }
    Ok(pt_len)
}

/// Signs ciphertext (not secret) using sender_sk's locked secret key.
/// Combined mode, matching the Python port -- see module docstring in
/// otp_transport.py for why (private FFI there had no detached-mode
/// export; here it does exist, but combined mode is used deliberately to
/// keep the two ports semantically matched).
pub fn sign_and_wrap(ciphertext: &[u8], sender_sk: &LockedBuffer) -> Result<Vec<u8>, TransportError> {
    if sender_sk.len() != sign_secretkeybytes() {
        return Err(TransportError::InvalidArgs("sender_sk wrong length".into()));
    }
    let mut sm = vec![0u8; ciphertext.len() + sign_bytes()];
    let mut smlen: u64 = 0;
    let rc = sign_combined(
        sm.as_mut_ptr(),
        &mut smlen as *mut u64,
        ciphertext.as_ptr(),
        ciphertext.len() as u64,
        sender_sk.as_slice().as_ptr(),
    );
    if rc != 0 {
        return Err(TransportError::SignFailed);
    }
    sm.truncate(smlen as usize);
    Ok(sm)
}

pub fn verify_and_unwrap(signed_ciphertext: &[u8], sender_pk: &[u8]) -> Result<Vec<u8>, TransportError> {
    if sender_pk.len() != sign_publickeybytes() {
        return Err(TransportError::InvalidArgs("sender_pk wrong length".into()));
    }
    if signed_ciphertext.len() < sign_bytes() {
        return Err(TransportError::InvalidArgs("signed_ciphertext shorter than SIGN_BYTES".into()));
    }
    let mut m = vec![0u8; signed_ciphertext.len()];
    let mut mlen: u64 = 0;
    let rc = sign_open_combined(
        m.as_mut_ptr(),
        &mut mlen as *mut u64,
        signed_ciphertext.as_ptr(),
        signed_ciphertext.len() as u64,
        sender_pk.as_ptr(),
    );
    if rc != 0 {
        return Err(TransportError::SignatureVerificationFailed);
    }
    m.truncate(mlen as usize);
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::locked_buffer::LockedBuffer;

    #[test]
    fn keypair_generation_distinct_and_correct_size() {
        let (pk_a, sk_a) = generate_box_keypair().unwrap();
        let (pk_b, _sk_b) = generate_box_keypair().unwrap();
        assert_eq!(pk_a.len(), 32);
        assert_eq!(sk_a.len(), 32);
        assert_ne!(pk_a.as_slice(), pk_b.as_slice(), "two independently generated keypairs produced identical public keys");
    }

    #[test]
    fn seal_open_round_trip() {
        let (pk_b, sk_b) = generate_box_keypair().unwrap();
        let plaintext = b"THIS IS SIMULATED PAD MATERIAL 0123456789ABCDEF".repeat(4);
        let mut pt_buf = LockedBuffer::new(plaintext.len()).unwrap();
        pt_buf.write_at(0, &plaintext).unwrap();

        let ciphertext = seal_pad(&pt_buf, plaintext.len(), pk_b.as_slice()).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + box_sealbytes());
        assert_ne!(ciphertext, plaintext);

        let mut out_buf = LockedBuffer::new(plaintext.len()).unwrap();
        let n = open_sealed(&ciphertext, &pk_b, &sk_b, &mut out_buf).unwrap();
        assert_eq!(&out_buf.as_slice()[..n], &plaintext[..]);
    }

    #[test]
    fn tampered_ciphertext_fails_closed() {
        let (pk_b, sk_b) = generate_box_keypair().unwrap();
        let plaintext = b"real pad data".to_vec();
        let mut pt_buf = LockedBuffer::new(plaintext.len()).unwrap();
        pt_buf.write_at(0, &plaintext).unwrap();
        let mut ciphertext = seal_pad(&pt_buf, plaintext.len(), pk_b.as_slice()).unwrap();
        ciphertext[5] ^= 0xFF;

        let mut out_buf = LockedBuffer::new(plaintext.len()).unwrap();
        match open_sealed(&ciphertext, &pk_b, &sk_b, &mut out_buf) {
            Err(TransportError::SealOpenFailed) => {}
            other => panic!("expected SealOpenFailed, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn wrong_keypair_fails_closed() {
        let (pk_b, _sk_b) = generate_box_keypair().unwrap();
        let (_pk_a, sk_a) = generate_box_keypair().unwrap();
        let plaintext = b"real pad data".to_vec();
        let mut pt_buf = LockedBuffer::new(plaintext.len()).unwrap();
        pt_buf.write_at(0, &plaintext).unwrap();
        let ciphertext = seal_pad(&pt_buf, plaintext.len(), pk_b.as_slice()).unwrap();

        let mut out_buf = LockedBuffer::new(plaintext.len()).unwrap();
        // A tries to open a box sealed for B, using A's own (wrong) sk
        match open_sealed(&ciphertext, &pk_b, &sk_a, &mut out_buf) {
            Err(TransportError::SealOpenFailed) => {}
            other => panic!("expected SealOpenFailed, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn full_sign_pipeline_round_trip() {
        let (box_pk_b, box_sk_b) = generate_box_keypair().unwrap();
        let (sign_pk_a, sign_sk_a) = generate_sign_keypair().unwrap();

        let plaintext = b"REAL PAD MATERIAL SEGMENT".to_vec();
        let mut pt_buf = LockedBuffer::new(plaintext.len()).unwrap();
        pt_buf.write_at(0, &plaintext).unwrap();
        let ciphertext = seal_pad(&pt_buf, plaintext.len(), box_pk_b.as_slice()).unwrap();

        let signed_ct = sign_and_wrap(&ciphertext, &sign_sk_a).unwrap();
        assert_eq!(signed_ct.len() - ciphertext.len(), sign_bytes());

        let recovered_ct = verify_and_unwrap(&signed_ct, sign_pk_a.as_slice()).unwrap();
        assert_eq!(recovered_ct, ciphertext);

        let mut out_buf = LockedBuffer::new(plaintext.len()).unwrap();
        let n = open_sealed(&recovered_ct, &box_pk_b, &box_sk_b, &mut out_buf).unwrap();
        assert_eq!(&out_buf.as_slice()[..n], &plaintext[..]);
    }

    #[test]
    fn tampered_signature_fails_closed() {
        let (sign_pk_a, sign_sk_a) = generate_sign_keypair().unwrap();
        let ciphertext = b"some ciphertext bytes".to_vec();
        let mut signed_ct = sign_and_wrap(&ciphertext, &sign_sk_a).unwrap();
        signed_ct[3] ^= 0xFF; // inside the signature portion (first sign_bytes())
        match verify_and_unwrap(&signed_ct, sign_pk_a.as_slice()) {
            Err(TransportError::SignatureVerificationFailed) => {}
            other => panic!("expected SignatureVerificationFailed, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn named_attack_payload_swap_from_different_sender_fails_closed() {
        let (sign_pk_a, sign_sk_a) = generate_sign_keypair().unwrap();
        let (sign_pk_c, sign_sk_c) = generate_sign_keypair().unwrap();

        let ciphertext_c = b"validly sealed payload from node C".to_vec();
        let signed_by_c = sign_and_wrap(&ciphertext_c, &sign_sk_c).unwrap();

        // Attacker presents C's fully valid signed block as though it came from A.
        match verify_and_unwrap(&signed_by_c, sign_pk_a.as_slice()) {
            Err(TransportError::SignatureVerificationFailed) => {}
            other => panic!("expected rejection when verifying C's payload against A's key, got {:?}", other.map(|_| ())),
        }
        // ...but it verifies correctly against its true sender C.
        let recovered = verify_and_unwrap(&signed_by_c, sign_pk_c.as_slice()).unwrap();
        assert_eq!(recovered, ciphertext_c);

        let _ = &sign_sk_a; // silence unused warning; kept for symmetry/clarity
    }
}
