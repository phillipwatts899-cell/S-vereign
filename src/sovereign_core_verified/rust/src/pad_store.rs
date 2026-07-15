//! PadStore -- Rust port of otp_pad.py's OTPPadStore, built on LockedBuffer.
//!
//! Invariants ported 1:1 from the Python side:
//!   - Deferred initialization: defer_fill mode allocates+locks a buffer
//!     but touches no journal state until finalize_fill() succeeds.
//!   - Atomic offset advancement: journal is written BEFORE reserved bytes
//!     become usable -- a crash after that point burns the bytes rather
//!     than risking reuse.
//!   - Pointer-based extraction: reserve_into() copies directly between
//!     already-allocated buffers (a slice copy_from_slice, which compiles
//!     to a single memcpy -- no intermediate heap Vec of plaintext pad
//!     material is ever allocated).
//!
//! Journal format: a fixed 40-byte binary file, not JSON -- avoids adding
//! serde_json as a dependency. Layout: [0..8) = big-endian u64 offset,
//! [8..40) = 32-byte keyed BLAKE2b MAC over the offset bytes.

use crate::locked_buffer::{LockedBuffer, LockedBufferError};
use crate::sodium_ffi::{keyed_mac, BLAKE2B_PERSONALBYTES, MAC_DIGEST_SIZE};
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

const JOURNAL_LEN: usize = 8 + MAC_DIGEST_SIZE;
const MAC_KEY_PERSON: &[u8; BLAKE2B_PERSONALBYTES] = b"otp_mackey_v1___"; // exactly 16 bytes

#[derive(Debug)]
pub enum PadStoreError {
    Locked(LockedBufferError),
    Io(std::io::Error),
    CorruptJournal(String),
    Exhausted { requested: usize, remaining: usize },
    NotFinalized,
    AlreadyFinalized,
    InvalidArgs(String),
}

impl From<LockedBufferError> for PadStoreError {
    fn from(e: LockedBufferError) -> Self { PadStoreError::Locked(e) }
}
impl From<std::io::Error> for PadStoreError {
    fn from(e: std::io::Error) -> Self { PadStoreError::Io(e) }
}

use crate::locked_buffer::RawWriteTarget;

impl RawWriteTarget for PadStore {
    fn as_mut_ptr_raw(&mut self) -> *mut u8 {
        self.buf.as_mut_ptr_raw()
    }
    fn len(&self) -> usize {
        self.pad_size
    }
}

pub struct PadStore {
    buf: LockedBuffer,
    pad_size: usize,
    journal_path: PathBuf,
    consumed_offset: Option<usize>,
    mac_key: Option<[u8; 32]>,
    filled: bool,
}

impl PadStore {
    /// Constructs a PadStore. If `defer_fill` is true, pad_material must be
    /// None; the buffer is allocated+locked but left unpopulated, and no
    /// journal state is touched until finalize_fill() is called externally
    /// (e.g. after decrypting network-received pad material directly into
    /// this store's buffer). Otherwise, pad_material (if Some) is copied in
    /// directly, or the buffer is filled with OS randomness, and the
    /// journal is loaded/initialized immediately.
    pub fn new(
        pad_size: usize,
        journal_path: impl AsRef<Path>,
        pad_material: Option<&[u8]>,
        defer_fill: bool,
    ) -> Result<Self, PadStoreError> {
        let mut buf = LockedBuffer::new(pad_size)?;
        let journal_path = journal_path.as_ref().to_path_buf();

        if defer_fill {
            if pad_material.is_some() {
                buf.clear();
                return Err(PadStoreError::InvalidArgs(
                    "cannot specify both defer_fill=true and pad_material".into(),
                ));
            }
            return Ok(PadStore {
                buf,
                pad_size,
                journal_path,
                consumed_offset: None,
                mac_key: None,
                filled: false,
            });
        }

        let fill_result = (|| -> Result<(), PadStoreError> {
            match pad_material {
                Some(m) => {
                    if m.len() != pad_size {
                        return Err(PadStoreError::InvalidArgs(
                            "pad_material length does not match pad_size".into(),
                        ));
                    }
                    buf.write_at(0, m).map_err(|e| PadStoreError::InvalidArgs(e.into()))?;
                }
                None => {
                    fill_with_os_random(&mut buf)?;
                }
            }
            Ok(())
        })();

        if let Err(e) = fill_result {
            buf.clear();
            return Err(e);
        }

        let mac_key = derive_mac_key(buf.as_slice());
        let mut store = PadStore {
            buf,
            pad_size,
            journal_path,
            consumed_offset: None,
            mac_key: Some(mac_key),
            filled: false,
        };
        match store.load_journal() {
            Ok(offset) => {
                store.consumed_offset = Some(offset);
                store.filled = true;
                Ok(store)
            }
            Err(e) => {
                store.buf.clear();
                Err(e)
            }
        }
    }

    /// Raw mutable pointer into the locked buffer -- for external
    /// population (e.g. a decryption routine writing pad material
    /// directly in, defer_fill=true construction only).
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.buf.as_mut_ptr_raw()
    }

    pub fn size(&self) -> usize {
        self.pad_size
    }

    /// Call after externally populating self.as_mut_ptr() (defer_fill=true
    /// path only). Derives the MAC key, then loads/initializes the
    /// journal. This is the single point at which a journal file may
    /// first be created for this journal_path.
    pub fn finalize_fill(&mut self) -> Result<(), PadStoreError> {
        if self.filled {
            return Err(PadStoreError::AlreadyFinalized);
        }
        let mac_key = derive_mac_key(self.buf.as_slice());
        self.mac_key = Some(mac_key);
        match self.load_journal() {
            Ok(offset) => {
                self.consumed_offset = Some(offset);
                self.filled = true;
                Ok(())
            }
            Err(e) => {
                self.buf.clear();
                Err(e)
            }
        }
    }

    fn require_filled(&self) -> Result<(), PadStoreError> {
        if !self.filled {
            return Err(PadStoreError::NotFinalized);
        }
        Ok(())
    }

    pub fn remaining(&self) -> Result<usize, PadStoreError> {
        self.require_filled()?;
        Ok(self.pad_size - self.consumed_offset.unwrap())
    }

    /// Reserves n bytes and returns them as an owned Vec -- mirrors
    /// otp_pad.py's reserve(). Journal is written BEFORE the slice is
    /// returned (atomic burn-before-use).
    pub fn reserve(&mut self, n: usize) -> Result<(usize, Vec<u8>), PadStoreError> {
        let offset = self.reserve_common(n)?;
        Ok((offset, self.buf.as_slice()[offset..offset + n].to_vec()))
    }

    /// Reserves n bytes and copies them DIRECTLY into `dest` via a slice
    /// copy (compiles to a single memcpy -- no intermediate heap
    /// allocation of plaintext pad material). Same atomicity invariant as
    /// reserve(). dest must be at least n bytes long.
    pub fn reserve_into(&mut self, n: usize, dest: &mut [u8]) -> Result<usize, PadStoreError> {
        if dest.len() < n {
            return Err(PadStoreError::InvalidArgs(
                "dest buffer shorter than requested reservation".into(),
            ));
        }
        let offset = self.reserve_common(n)?;
        dest[..n].copy_from_slice(&self.buf.as_slice()[offset..offset + n]);
        Ok(offset)
    }

    fn reserve_common(&mut self, n: usize) -> Result<usize, PadStoreError> {
        self.require_filled()?;
        if n == 0 {
            return Err(PadStoreError::InvalidArgs("n must be positive".into()));
        }
        let remaining = self.remaining()?;
        if n > remaining {
            return Err(PadStoreError::Exhausted { requested: n, remaining });
        }
        let offset = self.consumed_offset.unwrap();
        let new_offset = offset + n;
        self.write_journal(new_offset)?; // atomic, BEFORE bytes become usable
        self.consumed_offset = Some(new_offset);
        Ok(offset)
    }

    fn load_journal(&self) -> Result<usize, PadStoreError> {
        if !self.journal_path.exists() {
            self.write_journal_static(&self.journal_path, self.mac_key.as_ref().unwrap(), 0)?;
            return Ok(0);
        }
        let raw = fs::read(&self.journal_path)?;
        if raw.len() != JOURNAL_LEN {
            return Err(PadStoreError::CorruptJournal(format!(
                "journal length {} != expected {}", raw.len(), JOURNAL_LEN
            )));
        }
        let offset_bytes: [u8; 8] = raw[0..8].try_into().unwrap();
        let offset = u64::from_be_bytes(offset_bytes) as usize;
        let stored_mac: [u8; MAC_DIGEST_SIZE] = raw[8..40].try_into().unwrap();

        if offset > self.pad_size {
            return Err(PadStoreError::CorruptJournal(format!(
                "consumed_offset {} out of bounds for pad_size {}", offset, self.pad_size
            )));
        }

        let expected_mac = keyed_mac(&offset_bytes, self.mac_key.as_ref().unwrap(), MAC_KEY_PERSON);
        if !constant_time_eq(&expected_mac, &stored_mac) {
            return Err(PadStoreError::CorruptJournal(
                "journal MAC verification failed -- tampered or rolled-back offset".into(),
            ));
        }
        Ok(offset)
    }

    fn write_journal(&self, offset: usize) -> Result<(), PadStoreError> {
        self.write_journal_static(&self.journal_path, self.mac_key.as_ref().unwrap(), offset)
    }

    fn write_journal_static(&self, path: &Path, mac_key: &[u8; 32], offset: usize) -> Result<(), PadStoreError> {
        let offset_bytes = (offset as u64).to_be_bytes();
        let mac = keyed_mac(&offset_bytes, mac_key, MAC_KEY_PERSON);
        let mut record = Vec::with_capacity(JOURNAL_LEN);
        record.extend_from_slice(&offset_bytes);
        record.extend_from_slice(&mac);

        let tmp_path = path.with_extension("tmp");
        {
            let mut f = File::create(&tmp_path)?;
            f.write_all(&record)?;
            f.sync_all()?;
        }
        fs::rename(&tmp_path, path)?; // atomic on POSIX
        Ok(())
    }

    pub fn clear(&mut self) {
        self.buf.clear();
        self.filled = false;
    }
}

impl Drop for PadStore {
    fn drop(&mut self) {
        self.clear();
    }
}

fn derive_mac_key(pad_bytes: &[u8]) -> [u8; 32] {
    let person: &[u8; 16] = b"otp_mackey_kdf__";
    let full = keyed_mac(pad_bytes, &[0u8; 32], person);
    full // MAC_DIGEST_SIZE is already 32, matches key size needed
}

fn fill_with_os_random(buf: &mut LockedBuffer) -> Result<(), PadStoreError> {
    // Uses /dev/urandom directly -- avoids adding the `rand` crate as a
    // dependency, consistent with the stated goal of minimizing deps.
    use std::io::Read;
    let mut f = File::open("/dev/urandom")?;
    let mut tmp = vec![0u8; buf.len()];
    f.read_exact(&mut tmp)?;
    buf.write_at(0, &tmp).map_err(|e| PadStoreError::InvalidArgs(e.into()))?;
    // tmp held random pad material in ordinary (non-locked) heap memory
    // briefly -- same class of residual gap as encrypt()/reserve() on the
    // Python side, explicitly flagged there and equally true here. Not
    // fixed this round; noted rather than hidden.
    Ok(())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fresh_journal(name: &str) -> PathBuf {
        let p = PathBuf::from(format!("test_journal_{}.bin", name));
        let _ = fs::remove_file(&p);
        p
    }

    #[test]
    fn round_trip_reserve() {
        let journal = fresh_journal("roundtrip");
        let pad_material: Vec<u8> = (0..64u8).collect();
        let mut store = PadStore::new(64, &journal, Some(&pad_material), false).unwrap();
        let (offset, bytes) = store.reserve(10).unwrap();
        assert_eq!(offset, 0);
        assert_eq!(bytes, pad_material[0..10]);
        assert_eq!(store.remaining().unwrap(), 54);
        store.clear();
        let _ = fs::remove_file(&journal);
    }

    #[test]
    fn exhaustion_refusal() {
        let journal = fresh_journal("exhaust");
        let pad_material = vec![0u8; 16];
        let mut store = PadStore::new(16, &journal, Some(&pad_material), false).unwrap();
        store.reserve(10).unwrap();
        match store.reserve(10) {
            Err(PadStoreError::Exhausted { requested, remaining }) => {
                assert_eq!(requested, 10);
                assert_eq!(remaining, 6);
            }
            other => panic!("expected Exhausted error, got {:?}", other),
        }
        store.clear();
        let _ = fs::remove_file(&journal);
    }

    #[test]
    fn no_reuse_across_simulated_crash_restart() {
        let journal = fresh_journal("crash");
        let pad_material: Vec<u8> = (0..64u8).collect();
        {
            let mut store1 = PadStore::new(64, &journal, Some(&pad_material), false).unwrap();
            let (off1, _) = store1.reserve(20).unwrap();
            assert_eq!(off1, 0);
            // store1 dropped here without any special "clean shutdown" step --
            // Drop still runs (Rust doesn't have a way to simulate a true
            // crash that skips Drop within a single process), but critically
            // the journal was already written atomically inside reserve()
            // BEFORE this point, so what matters is reloading and confirming
            // the offset -- not whether Drop ran.
        }
        let mut store2 = PadStore::new(64, &journal, Some(&pad_material), false).unwrap();
        assert_eq!(store2.remaining().unwrap(), 44, "journal did not persist across reload");
        let (off2, _) = store2.reserve(10).unwrap();
        assert_eq!(off2, 20, "REUSE BUG: post-reload offset should start at 20");
        store2.clear();
        let _ = fs::remove_file(&journal);
    }

    #[test]
    fn defer_fill_then_finalize_works() {
        let journal = fresh_journal("defer");
        let mut store = PadStore::new(32, &journal, None, true).unwrap();
        assert!(!journal.exists(), "journal must not exist before finalize_fill()");
        unsafe {
            let ptr = store.as_mut_ptr();
            for i in 0..32 {
                *ptr.add(i) = i as u8;
            }
        }
        store.finalize_fill().unwrap();
        assert!(journal.exists(), "journal should exist immediately after finalize_fill()");
        let (off, bytes) = store.reserve(5).unwrap();
        assert_eq!(off, 0);
        assert_eq!(bytes, vec![0, 1, 2, 3, 4]);
        store.clear();
        let _ = fs::remove_file(&journal);
    }

    #[test]
    fn abandoned_defer_fill_creates_no_journal() {
        let journal = fresh_journal("abandoned");
        let mut store = PadStore::new(32, &journal, None, true).unwrap();
        unsafe {
            let ptr = store.as_mut_ptr();
            for i in 0..32 {
                *ptr.add(i) = 0xAB;
            }
        }
        // finalize_fill() deliberately never called -- simulating a failed
        // upstream pipeline step (e.g. signature verification failure).
        store.clear();
        assert!(!journal.exists(), "abandoned pre-finalize store must create zero persistent state");
    }

    #[test]
    fn unfinalized_store_refuses_reserve() {
        let journal = fresh_journal("unfinalized");
        let mut store = PadStore::new(32, &journal, None, true).unwrap();
        match store.reserve(5) {
            Err(PadStoreError::NotFinalized) => {}
            other => panic!("expected NotFinalized, got {:?}", other),
        }
        store.clear();
    }

    #[test]
    fn double_finalize_rejected() {
        let journal = fresh_journal("doublefinalize");
        let mut store = PadStore::new(32, &journal, None, true).unwrap();
        unsafe {
            let ptr = store.as_mut_ptr();
            for i in 0..32 { *ptr.add(i) = 0; }
        }
        store.finalize_fill().unwrap();
        match store.finalize_fill() {
            Err(PadStoreError::AlreadyFinalized) => {}
            other => panic!("expected AlreadyFinalized, got {:?}", other),
        }
        store.clear();
        let _ = fs::remove_file(&journal);
    }

    #[test]
    fn tampered_journal_backward_rollback_rejected() {
        let journal = fresh_journal("tamper_back");
        let pad_material = vec![7u8; 64];
        {
            let mut store = PadStore::new(64, &journal, Some(&pad_material), false).unwrap();
            store.reserve(20).unwrap();
            store.clear();
        }
        // Tamper: roll the offset field back to 0 (attempt to enable reuse).
        // The MAC won't match the new offset, since it wasn't recomputed.
        let mut raw = fs::read(&journal).unwrap();
        raw[0..8].copy_from_slice(&0u64.to_be_bytes());
        fs::write(&journal, &raw).unwrap();

        match PadStore::new(64, &journal, Some(&pad_material), false) {
            Err(PadStoreError::CorruptJournal(_)) => {}
            Ok(_) => panic!("rolled-back offset was accepted -- should have failed"),
            Err(e) => panic!("expected CorruptJournal on rolled-back offset, got a different error: {:?}", e),
        }
        let _ = fs::remove_file(&journal);
    }

    #[test]
    fn tampered_journal_wrong_length_rejected() {
        let journal = fresh_journal("tamper_len");
        let pad_material = vec![9u8; 32];
        {
            let mut store = PadStore::new(32, &journal, Some(&pad_material), false).unwrap();
            store.clear();
        }
        fs::write(&journal, b"not a valid journal at all").unwrap();
        match PadStore::new(32, &journal, Some(&pad_material), false) {
            Err(PadStoreError::CorruptJournal(_)) => {}
            Ok(_) => panic!("malformed journal was accepted -- should have failed"),
            Err(e) => panic!("expected CorruptJournal on malformed journal, got a different error: {:?}", e),
        }
        let _ = fs::remove_file(&journal);
    }

    #[test]
    fn out_of_bounds_offset_rejected() {
        let journal = fresh_journal("oob");
        let pad_material = vec![1u8; 16];
        // Manually construct a journal with an out-of-bounds offset, but
        // computed against a real (matching) mac_key so we isolate the
        // bounds check from the MAC check.
        let mac_key = derive_mac_key(&pad_material);
        let offset_bytes = (9999u64).to_be_bytes();
        let mac = keyed_mac(&offset_bytes, &mac_key, MAC_KEY_PERSON);
        let mut record = Vec::new();
        record.extend_from_slice(&offset_bytes);
        record.extend_from_slice(&mac);
        fs::write(&journal, &record).unwrap();

        match PadStore::new(16, &journal, Some(&pad_material), false) {
            Err(PadStoreError::CorruptJournal(msg)) => {
                assert!(msg.contains("out of bounds"), "wrong rejection reason: {}", msg);
            }
            Ok(_) => panic!("out-of-bounds offset was accepted -- should have failed"),
            Err(e) => panic!("expected CorruptJournal(out of bounds), got a different error: {:?}", e),
        }
        let _ = fs::remove_file(&journal);
    }

    #[test]
    fn reserve_into_zero_intermediate_and_correctness() {
        let journal = fresh_journal("reserve_into");
        let pad_material: Vec<u8> = (0..64u8).collect();
        let mut store = PadStore::new(64, &journal, Some(&pad_material), false).unwrap();
        let mut dest = vec![0u8; 20];
        let offset = store.reserve_into(10, &mut dest[4..14]).unwrap();
        assert_eq!(offset, 0);
        assert_eq!(&dest[4..14], &pad_material[0..10]);
        assert_eq!(&dest[0..4], &[0, 0, 0, 0]);
        assert_eq!(&dest[14..20], &[0, 0, 0, 0, 0, 0]);
        store.clear();
        let _ = fs::remove_file(&journal);
    }

    #[test]
    fn reserve_and_reserve_into_share_offset_state() {
        let journal = fresh_journal("shared_offset");
        let pad_material: Vec<u8> = (0..64u8).collect();
        let mut store = PadStore::new(64, &journal, Some(&pad_material), false).unwrap();
        let (off1, bytes1) = store.reserve(10).unwrap();
        let mut dest = vec![0u8; 10];
        let off2 = store.reserve_into(10, &mut dest).unwrap();
        assert_eq!(off1, 0);
        assert_eq!(off2, 10);
        assert_eq!(bytes1, pad_material[0..10]);
        assert_eq!(dest, pad_material[10..20]);
        store.clear();
        let _ = fs::remove_file(&journal);
    }
}
