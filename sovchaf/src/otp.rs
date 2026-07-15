use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
use otp_rust::locked_buffer::LockedBuffer;

type HmacSha256 = Hmac<Sha256>;
pub const SHARD_PAYLOAD_SIZE: usize = 1024;

#[derive(Clone, Debug)]
pub struct BotShard {
    pub session_id: [u8; 16],
    pub serial_idx: u64,
    pub shard_index: u32,
    pub total_shards: u32,
    pub total_plaintext_len: u64,
    pub counter_nonce: u64,
    pub checksum: [u8; 32],
    pub signature: [u8; 32],
    pub payload_slice: [u8; SHARD_PAYLOAD_SIZE],
}

impl Drop for BotShard {
    fn drop(&mut self) {
        unsafe {
            for i in 0..self.payload_slice.len() {
                std::ptr::write_volatile(&mut self.payload_slice[i], 0u8);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl BotShard {
    pub fn to_signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16 + 8 + 4 + 4 + 8 + 8 + 32 + SHARD_PAYLOAD_SIZE);
        buf.extend_from_slice(&self.session_id);
        buf.extend_from_slice(&self.serial_idx.to_be_bytes());
        buf.extend_from_slice(&self.shard_index.to_be_bytes());
        buf.extend_from_slice(&self.total_shards.to_be_bytes());
        buf.extend_from_slice(&self.total_plaintext_len.to_be_bytes());
        buf.extend_from_slice(&self.counter_nonce.to_be_bytes());
        buf.extend_from_slice(&self.checksum);
        buf.extend_from_slice(&self.payload_slice);
        buf
    }
}

pub struct ShardEngine {
    counter_path: PathBuf,
    current_key: LockedBuffer,
    counter_lock: Mutex<()>,
}

impl ShardEngine {
    pub fn init_from_storage<P: AsRef<Path>>(base_dir: P) -> io::Result<Self> {
        let base = base_dir.as_ref(); 
        let key_path = base.join("transport.key"); 
        let counter_path = base.join("transport.counter");
        
        let mut current_key = LockedBuffer::new(32).unwrap_or_else(|_| {
            unsafe { std::mem::transmute(vec![0u8; 32]) }
        });

        if key_path.exists() { 
            File::open(&key_path)?.read_exact(current_key.as_mut_slice())?; 
        } else { 
            if let Err(e) = otp_rust::entropy::JitterEntropyEngine::fill_with_hardware_jitter(current_key.as_mut_slice()) {
                return Err(io::Error::new(io::ErrorKind::Other, format!("Entropy engine failure: {:?}", e)));
            }
            File::create(&key_path)?.write_all(current_key.as_slice())?; 
        }

        if !counter_path.exists() { File::create(&counter_path)?.write_all(&0u64.to_be_bytes())?; }
        Ok(Self { counter_path, current_key, counter_lock: Mutex::new(()) })
    }

    pub fn reserve_counters(&self, count: u64) -> io::Result<u64> {
        let _guard = self.counter_lock.lock().unwrap();
        let mut f = OpenOptions::new().read(true).write(true).open(&self.counter_path)?;
        let mut buf = [0u8; 8]; f.read_exact(&mut buf)?;
        let current_counter = u64::from_be_bytes(buf);
        let next_counter = current_counter.checked_add(count).ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Overflow"))?;
        f.seek(SeekFrom::Start(0))?; f.write_all(&next_counter.to_be_bytes())?; f.sync_all()?;
        Ok(current_counter)
    }

    #[inline(always)]
    fn apply_kdf_timing_jitter(&self) {
        let mut ticks: u64 = 0;
        unsafe {
            #[cfg(target_arch = "aarch64")]
            std::arch::asm!("mrs {}, cntvct_el0", out(reg) ticks);
            #[cfg(target_arch = "x86_64")]
            std::arch::asm!("rdtsc", out("eax") ticks, out("edx") _);
        }
        let mask_delay = (ticks & 0x0F) as usize;
        for i in 0..mask_delay {
            std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
            let _ = i.wrapping_add(1);
        }
    }

    fn derive_instance_key(&self, serial_idx: u64, instance_label: &[u8]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(self.current_key.as_slice()).unwrap();
        mac.update(&serial_idx.to_be_bytes());
        mac.update(instance_label);
        
        self.apply_kdf_timing_jitter();
        
        let mut out = [0u8; 32];
        out.copy_from_slice(&mac.finalize().into_bytes()[0..32]);
        out
    }

    pub fn crypt_slice_payload(&self, payload: &mut [u8], serial_idx: u64) {
        let instance_key = self.derive_instance_key(serial_idx, b"secure-instance-keystream");
        for (sub_idx, chunk) in payload.chunks_mut(32).enumerate() {
            let mut mac = HmacSha256::new_from_slice(&instance_key).unwrap();
            mac.update(&sub_idx.to_be_bytes());
            self.apply_kdf_timing_jitter();
            let keystream = mac.finalize().into_bytes();
            for (byte, &ks_byte) in chunk.iter_mut().zip(keystream.iter()) { 
                *byte ^= ks_byte; 
            }
        }
    }

    pub fn sign_shard(&self, shard: &mut BotShard) {
        let instance_auth_key = self.derive_instance_key(shard.serial_idx, b"instance-mac-authentication");
        let mut mac = HmacSha256::new_from_slice(&instance_auth_key).unwrap();
        mac.update(&shard.to_signable_bytes());
        shard.signature.copy_from_slice(&mac.finalize().into_bytes()[0..32]);
    }

    pub fn verify_shard_signature(&self, shard: &BotShard) -> bool {
        let instance_auth_key = self.derive_instance_key(shard.serial_idx, b"instance-mac-authentication");
        let mut mac = HmacSha256::new_from_slice(&instance_auth_key).unwrap();
        mac.update(&shard.to_signable_bytes());
        let computed = mac.finalize().into_bytes();
        let mut acc = 0u8;
        for (a, b) in computed[0..32].iter().zip(shard.signature.iter()) { acc |= a ^ b; }
        acc == 0
    }

    pub fn build_outbound_packets(&self, session_id: [u8; 16], mut serial_idx: u64, plaintext: &[u8]) -> io::Result<Vec<BotShard>> {
        let total_shards = ((plaintext.len() + SHARD_PAYLOAD_SIZE - 1) / SHARD_PAYLOAD_SIZE).max(1);
        let mut shards = Vec::with_capacity(total_shards);
        let start_counter = self.reserve_counters(total_shards as u64)?;
        let total_plaintext_len = plaintext.len() as u64;
        for chunk_idx in 0..total_shards {
            let start = chunk_idx * SHARD_PAYLOAD_SIZE; 
            let end = (start + SHARD_PAYLOAD_SIZE).min(plaintext.len());
            let mut payload_slice = [0u8; SHARD_PAYLOAD_SIZE];
            if start < plaintext.len() { 
                payload_slice[..(end - start)].copy_from_slice(&plaintext[start..end]); 
            }
            let current_shard_nonce = start_counter + chunk_idx as u64;
            self.crypt_slice_payload(&mut payload_slice, serial_idx);
            let mut hasher = Sha256::new(); 
            hasher.update(&payload_slice);
            let checksum: [u8; 32] = hasher.finalize().into();
            let mut shard = BotShard { 
                session_id, 
                serial_idx, 
                shard_index: chunk_idx as u32, 
                total_shards: total_shards as u32, 
                total_plaintext_len, 
                counter_nonce: current_shard_nonce, 
                checksum, 
                signature: [0u8; 32], 
                payload_slice 
            };
            self.sign_shard(&mut shard); 
            shards.push(shard); 
            serial_idx += 1;
        }
        Ok(shards)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_multi_shard_and_out_of_order_reassembly() {
        let temp_dir = std::env::temp_dir();
        let unique_test_id = rand::random::<u64>();
        let test_run_path = temp_dir.join(format!("chaff_jitter_kdf_{}", unique_test_id));
        std::fs::create_dir_all(&test_run_path).unwrap();
        let engine = ShardEngine::init_from_storage(&test_run_path).unwrap();
        let original_msg = "A".repeat(1500);
        let session_id = [9; 16];
        let shards = engine.build_outbound_packets(session_id, 9000, original_msg.as_bytes()).unwrap();
        assert_eq!(shards.len(), 2);
        let first_shard = &shards[0];
        let second_shard = &shards[1];
        let mut session_map = HashMap::new();
        session_map.insert(second_shard.shard_index, second_shard.clone());
        session_map.insert(first_shard.shard_index, first_shard.clone());
        let mut complete_raw = Vec::with_capacity(2 * SHARD_PAYLOAD_SIZE);
        for i in 0..2 {
            let s = session_map.get(&i).unwrap();
            assert!(engine.verify_shard_signature(s));
            complete_raw.extend_from_slice(&s.payload_slice);
        }
        for i in 0..2 {
            let s = session_map.get(&i).unwrap();
            let offset = i as usize * SHARD_PAYLOAD_SIZE;
            let end = offset + SHARD_PAYLOAD_SIZE;
            engine.crypt_slice_payload(&mut complete_raw[offset..end], s.serial_idx);
        }
        let expected_len = first_shard.total_plaintext_len as usize;
        complete_raw.truncate(expected_len);
        let reconstructed_string = String::from_utf8(complete_raw).unwrap();
        assert_eq!(original_msg, reconstructed_string);
        let _ = std::fs::remove_dir_all(&test_run_path);
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use otp_rust::locked_buffer::{LockedBuffer, LockedBufferError};

    #[test]
    fn test_sovereign_core_memory_bridge() {
        match LockedBuffer::new(64) {
            Ok(mut secure_buf) => {
                let test_payload = [0xAAu8; 16];
                assert!(secure_buf.write_scarf(0, &test_payload).is_ok());
                let mut out_buffer = [0u8; 16];
                assert!(secure_buf.read_scarf(0, &mut out_buffer).is_ok());
                assert_eq!(out_buffer, test_payload);
                assert_eq!(secure_buf.len(), 64);
            }
Err(LockedBufferError::MlockFailed(e)) => {println!("System Notice: mlock bypassed due to platform constraints: {:?}", e);}Err(other) => {panic!("Unexpected hardware buffer defect: {:?}", other);}}}}
