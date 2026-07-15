//! Minimal hand-written FFI bindings against the SYSTEM libsodium, linked
//! directly (no libsodium-sys crate) -- mirrors the Python side's approach
//! of using raw _sodium.lib FFI rather than a higher-level wrapper.
//! Signatures verified against the real header (/usr/include/sodium/
//! crypto_generichash_blake2b.h), not reconstructed from memory.

#[link(name = "sodium")]
extern "C" {
    fn crypto_generichash_blake2b_salt_personal(
        out: *mut u8,
        outlen: usize,
        input: *const u8,
        inlen: u64,
        key: *const u8,
        keylen: usize,
        salt: *const u8,
        personal: *const u8,
    ) -> i32;
}

pub const BLAKE2B_SALTBYTES: usize = 16;
pub const BLAKE2B_PERSONALBYTES: usize = 16;
pub const MAC_DIGEST_SIZE: usize = 32;

/// Keyed BLAKE2b MAC over `data`, domain-separated via a 16-byte personal
/// string. Returns a fixed 32-byte digest. Panics only on a libsodium
/// return code we don't expect (i.e., an actual FFI contract violation,
/// not a runtime/business-logic failure -- those are all encoded as
/// Result elsewhere in this crate).
pub fn keyed_mac(data: &[u8], key: &[u8; 32], person: &[u8; BLAKE2B_PERSONALBYTES]) -> [u8; MAC_DIGEST_SIZE] {
    let mut out = [0u8; MAC_DIGEST_SIZE];
    let salt = [0u8; BLAKE2B_SALTBYTES];
    let rc = unsafe {
        crypto_generichash_blake2b_salt_personal(
            out.as_mut_ptr(),
            MAC_DIGEST_SIZE,
            data.as_ptr(),
            data.len() as u64,
            key.as_ptr(),
            key.len(),
            salt.as_ptr(),
            person.as_ptr(),
        )
    };
    assert_eq!(rc, 0, "crypto_generichash_blake2b_salt_personal returned nonzero -- FFI contract violation");
    out
}

/// Unkeyed BLAKE2b hash -- distinct construction from keyed_mac, not the
/// same thing with a zero key. Used for fail-fast corruption/injection
/// detection where no secret-keyed authentication boundary is intended
/// (that guarantee lives elsewhere, e.g. the Ed25519 signature checked
/// after chunk reassembly). Matches otp_chunking.py's _chunk_hash, which
/// calls the Python wrapper with no key argument (defaults to key=b"").
pub fn unkeyed_hash(data: &[u8], person: &[u8; BLAKE2B_PERSONALBYTES]) -> [u8; MAC_DIGEST_SIZE] {
    let mut out = [0u8; MAC_DIGEST_SIZE];
    let salt = [0u8; BLAKE2B_SALTBYTES];
    let rc = unsafe {
        crypto_generichash_blake2b_salt_personal(
            out.as_mut_ptr(),
            MAC_DIGEST_SIZE,
            data.as_ptr(),
            data.len() as u64,
            std::ptr::null(),
            0,
            salt.as_ptr(),
            person.as_ptr(),
        )
    };
    assert_eq!(rc, 0, "crypto_generichash_blake2b_salt_personal returned nonzero -- FFI contract violation");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyed_mac_deterministic_and_key_sensitive() {
        let person = *b"otp_journal_v1__";
        let key1 = [0x11u8; 32];
        let key2 = [0x22u8; 32];
        let data = b"consumed_offset=20";

        let m1a = keyed_mac(data, &key1, &person);
        let m1b = keyed_mac(data, &key1, &person);
        let m2 = keyed_mac(data, &key2, &person);

        assert_eq!(m1a, m1b, "same key+data must produce identical MAC");
        assert_ne!(m1a, m2, "different key must produce different MAC");
        assert_eq!(m1a.len(), 32);
    }

    #[test]
    fn keyed_mac_sensitive_to_message() {
        let person = *b"otp_journal_v1__";
        let key = [0x33u8; 32];
        let m1 = keyed_mac(b"consumed_offset=20", &key, &person);
        let m2 = keyed_mac(b"consumed_offset=21", &key, &person);
        assert_ne!(m1, m2, "different message must produce different MAC");
    }
}

#[link(name = "sodium")]
extern "C" {
    fn crypto_box_publickeybytes() -> usize;
    fn crypto_box_secretkeybytes() -> usize;
    fn crypto_box_sealbytes() -> usize;
    fn crypto_box_keypair(pk: *mut u8, sk: *mut u8) -> i32;
    fn crypto_box_seal(c: *mut u8, m: *const u8, mlen: u64, pk: *const u8) -> i32;
    fn crypto_box_seal_open(m: *mut u8, c: *const u8, clen: u64, pk: *const u8, sk: *const u8) -> i32;

    fn crypto_sign_bytes() -> usize;
    fn crypto_sign_publickeybytes() -> usize;
    fn crypto_sign_secretkeybytes() -> usize;
    fn crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> i32;
    fn crypto_sign(sm: *mut u8, smlen_p: *mut u64, m: *const u8, mlen: u64, sk: *const u8) -> i32;
    fn crypto_sign_open(m: *mut u8, mlen_p: *mut u64, sm: *const u8, smlen: u64, pk: *const u8) -> i32;
}

pub fn box_publickeybytes() -> usize { unsafe { crypto_box_publickeybytes() } }
pub fn box_secretkeybytes() -> usize { unsafe { crypto_box_secretkeybytes() } }
pub fn box_sealbytes() -> usize { unsafe { crypto_box_sealbytes() } }
pub fn sign_bytes() -> usize { unsafe { crypto_sign_bytes() } }
pub fn sign_publickeybytes() -> usize { unsafe { crypto_sign_publickeybytes() } }
pub fn sign_secretkeybytes() -> usize { unsafe { crypto_sign_secretkeybytes() } }

pub fn box_keypair(pk: *mut u8, sk: *mut u8) -> i32 {
    unsafe { crypto_box_keypair(pk, sk) }
}
pub fn box_seal(c: *mut u8, m: *const u8, mlen: u64, pk: *const u8) -> i32 {
    unsafe { crypto_box_seal(c, m, mlen, pk) }
}
pub fn box_seal_open(m: *mut u8, c: *const u8, clen: u64, pk: *const u8, sk: *const u8) -> i32 {
    unsafe { crypto_box_seal_open(m, c, clen, pk, sk) }
}
pub fn sign_keypair(pk: *mut u8, sk: *mut u8) -> i32 {
    unsafe { crypto_sign_keypair(pk, sk) }
}
pub fn sign_combined(sm: *mut u8, smlen_p: *mut u64, m: *const u8, mlen: u64, sk: *const u8) -> i32 {
    unsafe { crypto_sign(sm, smlen_p, m, mlen, sk) }
}
pub fn sign_open_combined(m: *mut u8, mlen_p: *mut u64, sm: *const u8, smlen: u64, pk: *const u8) -> i32 {
    unsafe { crypto_sign_open(m, mlen_p, sm, smlen, pk) }
}

#[cfg(test)]
mod transport_ffi_tests {
    use super::*;

    #[test]
    fn size_queries_match_known_libsodium_values() {
        // Cross-check against the values already empirically confirmed on
        // the Python side this session (nacl.bindings introspection) --
        // not trusted blindly here either, just corroborated.
        assert_eq!(box_publickeybytes(), 32);
        assert_eq!(box_secretkeybytes(), 32);
        assert_eq!(box_sealbytes(), 48);
        assert_eq!(sign_bytes(), 64);
        assert_eq!(sign_publickeybytes(), 32);
        assert_eq!(sign_secretkeybytes(), 64);
    }
}
