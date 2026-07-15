//! stream_adapter.rs -- continuous byte-stream (pipe/serial) transport.
//!
//! Framing: length-prefixed using each chunk's OWN embedded header, not a
//! delimiter byte -- chunk payloads are ciphertext and can contain any
//! byte value, so a delimiter would require escaping. Every chunk already
//! carries its own payload_len field; read_chunk_from_stream reads
//! HEADER_LEN bytes, parses that field, then reads exactly
//! payload_len + CHUNK_HASH_LEN more.
//!
//! EOF handling: a clean end-of-stream BETWEEN chunks (zero bytes read
//! when a new chunk was expected to start) is normal and yields None. An
//! EOF encountered PARTWAY through a chunk's header or body is framing
//! loss -- a real error, never silently treated as "no more chunks."

use crate::chunking::{CHUNK_HASH_LEN, HEADER_LEN, SESSION_ID_LEN};
use std::io::{self, Read, Write};

/// Sane upper bound on a single chunk's declared payload_len, checked
/// BEFORE any allocation is attempted -- same DoS-resistance principle as
/// chunking.rs's total_chunks bound, applied here to the length-prefix
/// field instead.
pub const MAX_REASONABLE_CHUNK_PAYLOAD: usize = 10 * 1024 * 1024; // 10 MiB

#[derive(Debug)]
pub enum StreamAdapterError {
    Io(io::Error),
    UnexpectedEof(String),
    MalformedLength(String),
}

impl From<io::Error> for StreamAdapterError {
    fn from(e: io::Error) -> Self { StreamAdapterError::Io(e) }
}

pub fn write_chunk_to_stream<W: Write>(w: &mut W, chunk: &[u8]) -> io::Result<()> {
    // Chunks are already self-describing (header includes payload_len) --
    // no additional framing needed on the write side.
    w.write_all(chunk)
}

/// Loops to fill `buf` completely, correctly handling partial reads.
/// Returns Ok(true) if `buf` was fully filled, Ok(false) if the stream hit
/// a clean EOF before ANY bytes were read (i.e. no chunk was starting),
/// or Err(UnexpectedEof) if EOF hit after SOME but not all bytes were
/// read (framing loss mid-header).
fn read_exact_or_clean_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<bool, StreamAdapterError> {
    let mut total_read = 0;
    while total_read < buf.len() {
        let n = r.read(&mut buf[total_read..])?;
        if n == 0 {
            if total_read == 0 {
                return Ok(false);
            }
            return Err(StreamAdapterError::UnexpectedEof(format!(
                "stream ended after {} of {} expected bytes", total_read, buf.len()
            )));
        }
        total_read += n;
    }
    Ok(true)
}

/// Reads exactly one chunk from the stream. Returns Ok(None) on a clean
/// end-of-stream between chunks (no more data). Returns
/// Err(UnexpectedEof) if the stream ends partway through a chunk.
pub fn read_chunk_from_stream<R: Read>(r: &mut R) -> Result<Option<Vec<u8>>, StreamAdapterError> {
    let mut header = vec![0u8; HEADER_LEN];
    if !read_exact_or_clean_eof(r, &mut header)? {
        return Ok(None); // clean end between chunks
    }

    let len_off = SESSION_ID_LEN + 4 + 4; // past session_id, seq, total
    let payload_len = u32::from_be_bytes(header[len_off..len_off + 4].try_into().unwrap()) as usize;

    if payload_len > MAX_REASONABLE_CHUNK_PAYLOAD {
        return Err(StreamAdapterError::MalformedLength(format!(
            "declared payload_len {} exceeds sane per-chunk bound {}", payload_len, MAX_REASONABLE_CHUNK_PAYLOAD
        )));
    }

    let mut rest = vec![0u8; payload_len + CHUNK_HASH_LEN];
    if !read_exact_or_clean_eof(r, &mut rest)? {
        return Err(StreamAdapterError::UnexpectedEof(
            "stream ended immediately after header, before payload+hash".into(),
        ));
    }

    let mut full = header;
    full.extend_from_slice(&rest);
    Ok(Some(full))
}

/// Iterator wrapper -- yields Ok(chunk) per chunk, stops (None) on clean
/// EOF between chunks, yields Some(Err(..)) on any framing/length error.
pub struct ChunkStreamReader<R: Read> {
    inner: R,
}

impl<R: Read> ChunkStreamReader<R> {
    pub fn new(inner: R) -> Self {
        ChunkStreamReader { inner }
    }
}

impl<R: Read> Iterator for ChunkStreamReader<R> {
    type Item = Result<Vec<u8>, StreamAdapterError>;
    fn next(&mut self) -> Option<Self::Item> {
        match read_chunk_from_stream(&mut self.inner) {
            Ok(Some(chunk)) => Some(Ok(chunk)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunking::{encode_chunks, ChunkReassembler};
    use crate::export::export_pad_payload;
    use crate::ingest::ingest_assembled_payload;
    use crate::pad_store::PadStore;
    use crate::transport::{generate_box_keypair, generate_sign_keypair};
    use std::io::Cursor;
    use std::os::unix::io::FromRawFd;

    /// Wraps any Read and limits EVERY underlying read() call to at most
    /// `max_per_call` bytes, regardless of the buffer size requested by
    /// the caller. Deterministically forces the accumulation loops in
    /// read_exact_or_clean_eof to actually loop, rather than depending on
    /// whatever buffering behavior the OS/Cursor happens to exhibit.
    struct FragmentedReader<R: Read> {
        inner: R,
        max_per_call: usize,
    }
    impl<R: Read> Read for FragmentedReader<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let cap = self.max_per_call.min(buf.len());
            self.inner.read(&mut buf[..cap])
        }
    }

    fn real_pipe() -> (std::fs::File, std::fs::File) {
        let mut fds: [i32; 2] = [0, 0];
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "libc::pipe() failed");
        let read_end = unsafe { std::fs::File::from_raw_fd(fds[0]) };
        let write_end = unsafe { std::fs::File::from_raw_fd(fds[1]) };
        (read_end, write_end)
    }

    #[test]
    fn happy_path_in_memory_cursor() {
        let payload: Vec<u8> = (0..200u8).collect();
        let chunks = encode_chunks(&payload, 40, None);

        let mut buf = Vec::new();
        for c in &chunks {
            write_chunk_to_stream(&mut buf, c).unwrap();
        }

        let cursor = Cursor::new(buf);
        let reader = ChunkStreamReader::new(cursor);
        let read_back: Result<Vec<Vec<u8>>, StreamAdapterError> = reader.collect();
        let read_back = read_back.unwrap();

        assert_eq!(read_back, chunks);
    }

    #[test]
    fn real_os_pipe_full_transfer() {
        let payload: Vec<u8> = (0..150u8).collect();
        let chunks = encode_chunks(&payload, 40, None);
        let (read_end, mut write_end) = real_pipe();

        for c in &chunks {
            write_chunk_to_stream(&mut write_end, c).unwrap();
        }
        drop(write_end); // close write end -- signals EOF to the reader

        let reader = ChunkStreamReader::new(read_end);
        let read_back: Result<Vec<Vec<u8>>, StreamAdapterError> = reader.collect();
        let read_back = read_back.unwrap();

        assert_eq!(read_back, chunks, "real OS pipe transfer did not preserve chunk content exactly");
    }

    #[test]
    fn artificial_byte_at_a_time_fragmentation() {
        let payload: Vec<u8> = (0..200u8).collect();
        let chunks = encode_chunks(&payload, 40, None);

        let mut buf = Vec::new();
        for c in &chunks {
            write_chunk_to_stream(&mut buf, c).unwrap();
        }

        // Force every single read() call to return at most 2 bytes,
        // regardless of how many the caller asked for.
        let fragmented = FragmentedReader { inner: Cursor::new(buf), max_per_call: 2 };
        let reader = ChunkStreamReader::new(fragmented);
        let read_back: Result<Vec<Vec<u8>>, StreamAdapterError> = reader.collect();
        let read_back = read_back.unwrap();

        assert_eq!(read_back, chunks, "2-bytes-per-read fragmentation broke chunk reconstruction");
    }

    #[test]
    fn framing_loss_mid_chunk_is_a_real_error_not_a_clean_end() {
        let payload: Vec<u8> = (0..200u8).collect();
        let chunks = encode_chunks(&payload, 40, None);

        let mut buf = Vec::new();
        write_chunk_to_stream(&mut buf, &chunks[0]).unwrap();
        // Start writing chunk 1 but cut it off partway through -- simulates
        // a dropped connection / lost bytes mid-frame.
        buf.extend_from_slice(&chunks[1][..HEADER_LEN + 5]);

        let cursor = Cursor::new(buf);
        let mut reader = ChunkStreamReader::new(cursor);

        assert!(matches!(reader.next(), Some(Ok(_))), "first complete chunk should read fine");
        match reader.next() {
            Some(Err(StreamAdapterError::UnexpectedEof(_))) => {}
            other => panic!("expected UnexpectedEof on mid-chunk truncation, got {:?}", other.map(|r| r.map(|_| ()))),
        }
    }

    #[test]
    fn clean_eof_between_chunks_yields_none_not_an_error() {
        let payload: Vec<u8> = (0..80u8).collect();
        let chunks = encode_chunks(&payload, 40, None);
        assert!(chunks.len() >= 2);

        let mut buf = Vec::new();
        for c in &chunks {
            write_chunk_to_stream(&mut buf, c).unwrap();
        }
        // No trailing partial data -- stream ends EXACTLY at a chunk boundary.

        let cursor = Cursor::new(buf);
        let mut reader = ChunkStreamReader::new(cursor);
        for _ in 0..chunks.len() {
            assert!(matches!(reader.next(), Some(Ok(_))));
        }
        assert!(reader.next().is_none(), "clean end-of-stream after the last chunk must yield None, not an error");
    }

    #[test]
    fn dos_bound_on_declared_payload_len_rejected_before_allocation() {
        // Forge a header claiming an absurd payload_len, followed by only
        // a few real bytes -- if the length check happened AFTER trying to
        // allocate/read that many bytes, this would hang or attempt a
        // huge allocation. It must be rejected immediately instead.
        let mut forged_header = vec![0u8; HEADER_LEN];
        forged_header[0..SESSION_ID_LEN].copy_from_slice(&[1u8; SESSION_ID_LEN]);
        let len_off = SESSION_ID_LEN + 4 + 4;
        forged_header[len_off..len_off + 4].copy_from_slice(&(4_000_000_000u32).to_be_bytes());

        let mut buf = forged_header;
        buf.extend_from_slice(b"only a few trailing bytes"); // nowhere near 4 billion

        let cursor = Cursor::new(buf);
        let mut reader = ChunkStreamReader::new(cursor);
        match reader.next() {
            Some(Err(StreamAdapterError::MalformedLength(_))) => {}
            other => panic!("expected MalformedLength rejected before allocation, got {:?}", other.map(|r| r.map(|_| ()))),
        }
    }

    #[test]
    fn full_closed_loop_through_real_pipe() {
        let (box_pk_b, box_sk_b) = generate_box_keypair().unwrap();
        let (sign_pk_a, sign_sk_a) = generate_sign_keypair().unwrap();

        let sender_journal = "stream_closedloop_sender.bin".to_string();
        let receiver_journal = "stream_closedloop_receiver.bin".to_string();
        let _ = std::fs::remove_file(&sender_journal);
        let _ = std::fs::remove_file(&receiver_journal);

        let mut urandom = std::fs::File::open("/dev/urandom").unwrap();
        let mut sender_pad_material = vec![0u8; 200];
        urandom.read_exact(&mut sender_pad_material).unwrap();
        let mut sender_store = PadStore::new(200, &sender_journal, Some(&sender_pad_material), false).unwrap();

        let (_, chunks) = export_pad_payload(&mut sender_store, 50, box_pk_b.as_slice(), &sign_sk_a, 30, None).unwrap();

        let (read_end, mut write_end) = real_pipe();
        for c in &chunks {
            write_chunk_to_stream(&mut write_end, c).unwrap();
        }
        drop(write_end);

        let reader = ChunkStreamReader::new(read_end);
        let mut reassembler = ChunkReassembler::default();
        for chunk_result in reader {
            let chunk = chunk_result.unwrap();
            reassembler.ingest(&chunk).unwrap();
        }

        let mut receiver_store = PadStore::new(50, &receiver_journal, None, true).unwrap();
        ingest_assembled_payload(&reassembler, sign_pk_a.as_slice(), &box_pk_b, &box_sk_b, &mut receiver_store).unwrap();

        let (_, received) = receiver_store.reserve(50).unwrap();
        assert_eq!(received, sender_pad_material[0..50], "real-pipe round trip corrupted the pad material");

        sender_store.clear();
        receiver_store.clear();
        let _ = std::fs::remove_file(&sender_journal);
        let _ = std::fs::remove_file(&receiver_journal);
    }
}
