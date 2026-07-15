use std::io::{self, Read, Write};
use otp_rust::locked_buffer::LockedBuffer;

pub const HEADER_LEN: usize = 32;
pub const MAX_ALLOWED_PAYLOAD: u32 = 10 * 1024 * 1024;

struct SimplePrng {
    state: u64,
}

impl SimplePrng {
    fn new(seed: u64) -> Self {
        Self { state: seed ^ 0x5A5A5A5A5A5A5A5A }
    }
    
    fn next_u32(&mut self) -> u32 {
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (self.state >> 32) as u32
    }
}

pub struct StealthChaffWriter<W: Write> {
    inner: W,
    prng: SimplePrng,
}

impl<W: Write> StealthChaffWriter<W> {
    pub fn new(inner: W, seed: u64) -> Self {
        Self { inner, prng: SimplePrng::new(seed) }
    }

    pub fn transmit_stealth(&mut self, header: &[u8; HEADER_LEN], payload: &[u8]) -> io::Result<()> {
        if payload.len() > MAX_ALLOWED_PAYLOAD as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Payload size breach"));
        }
        let chaff_count = ((self.prng.next_u32() % 3) + 1) as usize;
        for _ in 0..chaff_count {
            self.write_stealth_chaff_frame(payload.len())?;
        }
        self.write_stealth_envelope(header, payload)?;
        Ok(())
    }

    fn write_stealth_envelope(&mut self, header: &[u8; HEADER_LEN], payload: &[u8]) -> io::Result<()> {
        let mut raw_packet = Vec::with_capacity(HEADER_LEN + 4 + payload.len());
        raw_packet.extend_from_slice(header);
        raw_packet.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        raw_packet.extend_from_slice(payload);

        let mut out = String::new();
        let mut chunks = raw_packet.chunks_exact(3);
        const CHARSET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for chunk in &mut chunks {
            let b = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | (chunk[2] as u32);
            out.push(CHARSET[((b >> 18) & 63) as usize] as char);
            out.push(CHARSET[((b >> 12) & 63) as usize] as char);
            out.push(CHARSET[((b >> 6) & 63) as usize] as char);
            out.push(CHARSET[(b & 63) as usize] as char);
        }
        let mock_line = format!("[SYS_DIAG_LOG] TYPE=WHEAT TIMESTAMP={} DATA={}\n", self.prng.next_u32(), out);
        self.inner.write_all(mock_line.as_bytes())?;
        self.inner.flush()
    }

    fn write_stealth_chaff_frame(&mut self, size: usize) -> io::Result<()> {
        let total_binary_size = HEADER_LEN + 4 + size;
        let mut dummy_res = LockedBuffer::new(total_binary_size)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Secure space allocation fault"))?;
        let mock_line = format!("[SYS_DIAG_LOG] TYPE=CHAFF TIMESTAMP={} DATA=DUMMY\n", self.prng.next_u32());
        self.inner.write_all(mock_line.as_bytes())?;
        self.inner.flush()
    }
}
