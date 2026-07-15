//! optical_adapter.rs -- optical/QR-frame transport (design + deterministic
//! serialization layer only -- no camera/video capture pipeline exists in
//! this sandbox, so nothing about actual frame rendering or scanning is
//! claimed or tested here; only the data serialization/reassembly logic,
//! which IS fully execution-verified).
//!
//! Frame layout: magic(4) || session_tag(4) || sequence_idx(4) ||
//! total_frames(4) || chunk_payload. Currently 1 optical frame = exactly
//! 1 full chunking::encode_chunks() chunk (no fragmentation of one chunk
//! across multiple frames). Because of that 1:1 mapping, sequence_idx and
//! total_frames here are REDUNDANT with the chunk's own embedded seq/total
//! fields -- deliberately kept anyway, repurposed as a cross-validation
//! check: the reassembler rejects a frame if its optical-layer seq doesn't
//! match the seq embedded in the chunk it's carrying, catching tampering
//! or a mismatched wrapper rather than just duplicating information.
//!
//! session_tag defends against the same class of attack chunking.rs's
//! session_id defends against: frames captured from two different visual
//! streams (two overlapping QR loops, or a stale loop still playing on a
//! second screen) must not be silently merged into one reassembly.

use crate::chunking::{HEADER_LEN as CHUNK_HEADER_LEN, SESSION_ID_LEN};
use std::collections::HashMap;

pub const QR_MAX_CAPACITY_V40_LOW_REC: usize = 2953; // verified: ISO/IEC 18004, V40-L, byte mode
pub const OPTICAL_FRAME_HEADER_LEN: usize = 16; // 4 magic + 4 session_tag + 4 seq + 4 total
const MAGIC: &[u8; 4] = b"QRST";

#[derive(Debug)]
pub enum OpticalEncoderError {
    ChunkTooLargeForMedium { size: usize, max: usize },
    InvalidMaxFrameSize { requested: usize, ceiling: usize },
}

#[derive(Debug)]
pub enum OpticalReassemblerError {
    Malformed(String),
    BadMagic,
    SessionMismatch { expected: u32, got: u32 },
    TotalMismatch { expected: u32, got: u32 },
    SeqCrossValidationFailed { optical_seq: u32, embedded_chunk_seq: u32 },
    IndexOutOfRange { seq: u32, total: u32 },
}

pub struct OpticalFrameEncoder {
    max_frame_size: usize,
    session_tag: u32,
}

impl OpticalFrameEncoder {
    /// Fails loudly (does not silently clamp) if max_frame_size exceeds
    /// the QR V40-L physical ceiling -- a caller who configured a specific
    /// size should be told, not silently downgraded.
    pub fn new(max_frame_size: usize, session_tag: u32) -> Result<Self, OpticalEncoderError> {
        if max_frame_size > QR_MAX_CAPACITY_V40_LOW_REC {
            return Err(OpticalEncoderError::InvalidMaxFrameSize {
                requested: max_frame_size,
                ceiling: QR_MAX_CAPACITY_V40_LOW_REC,
            });
        }
        Ok(Self { max_frame_size, session_tag })
    }

    pub fn encode_frame(&self, sequence_idx: u32, total_frames: u32, chunk_payload: &[u8]) -> Result<Vec<u8>, OpticalEncoderError> {
        let required_space = chunk_payload.len() + OPTICAL_FRAME_HEADER_LEN;
        if required_space > self.max_frame_size {
            return Err(OpticalEncoderError::ChunkTooLargeForMedium {
                size: required_space,
                max: self.max_frame_size,
            });
        }

        let mut frame = Vec::with_capacity(required_space);
        frame.extend_from_slice(MAGIC);
        frame.extend_from_slice(&self.session_tag.to_be_bytes());
        frame.extend_from_slice(&sequence_idx.to_be_bytes());
        frame.extend_from_slice(&total_frames.to_be_bytes());
        frame.extend_from_slice(chunk_payload);
        Ok(frame)
    }
}

/// Buffers optical frames by their embedded sequence index, tolerating
/// arbitrary arrival order and exact-duplicate captures (a camera
/// re-scanning the same on-screen frame is normal, not an error). Once
/// every expected frame has arrived, emits the underlying chunks in
/// correct ascending order, ready for chunking::ChunkReassembler.
pub struct OpticalFrameReassembler {
    session_tag: Option<u32>,
    total_frames: Option<u32>,
    received: HashMap<u32, Vec<u8>>, // seq -> chunk_payload (frame header stripped)
}

impl OpticalFrameReassembler {
    pub fn new() -> Self {
        OpticalFrameReassembler { session_tag: None, total_frames: None, received: HashMap::new() }
    }

    /// Returns Ok(true) once every expected frame (0..total_frames) has
    /// been received. Duplicate captures of an already-received seq are
    /// silently accepted as a no-op (not an error) -- idempotent, since
    /// re-scanning the same visual frame is expected behavior, not an
    /// attack. A duplicate with DIFFERENT content at the same seq (which
    /// would indicate real tampering, not just a re-scan) IS rejected.
    pub fn ingest_frame(&mut self, raw_frame: &[u8]) -> Result<bool, OpticalReassemblerError> {
        if raw_frame.len() < OPTICAL_FRAME_HEADER_LEN {
            return Err(OpticalReassemblerError::Malformed("frame shorter than header length".into()));
        }
        if &raw_frame[0..4] != MAGIC {
            return Err(OpticalReassemblerError::BadMagic);
        }
        let session_tag = u32::from_be_bytes(raw_frame[4..8].try_into().unwrap());
        let seq = u32::from_be_bytes(raw_frame[8..12].try_into().unwrap());
        let total = u32::from_be_bytes(raw_frame[12..16].try_into().unwrap());
        let chunk_payload = &raw_frame[OPTICAL_FRAME_HEADER_LEN..];

        match self.session_tag {
            None => {
                self.session_tag = Some(session_tag);
                self.total_frames = Some(total);
            }
            Some(existing) => {
                if session_tag != existing {
                    return Err(OpticalReassemblerError::SessionMismatch { expected: existing, got: session_tag });
                }
                if Some(total) != self.total_frames {
                    return Err(OpticalReassemblerError::TotalMismatch {
                        expected: self.total_frames.unwrap(), got: total,
                    });
                }
            }
        }

        if seq >= total {
            return Err(OpticalReassemblerError::IndexOutOfRange { seq, total });
        }

        // Cross-validate: the optical-layer seq must match the seq
        // embedded in the chunk it's carrying (chunking.rs's own header,
        // starting right after the chunk's session_id field).
        if chunk_payload.len() >= CHUNK_HEADER_LEN {
            let embedded_seq_off = SESSION_ID_LEN;
            let embedded_seq = u32::from_be_bytes(
                chunk_payload[embedded_seq_off..embedded_seq_off + 4].try_into().unwrap()
            );
            if embedded_seq != seq {
                return Err(OpticalReassemblerError::SeqCrossValidationFailed {
                    optical_seq: seq, embedded_chunk_seq: embedded_seq,
                });
            }
        } else {
            return Err(OpticalReassemblerError::Malformed(
                "chunk_payload shorter than the inner chunk's own header -- cannot cross-validate".into(),
            ));
        }

        match self.received.get(&seq) {
            Some(existing) if existing == chunk_payload => {
                // Exact duplicate capture -- idempotent no-op.
            }
            Some(_) => {
                return Err(OpticalReassemblerError::Malformed(format!(
                    "seq {} received twice with DIFFERENT content -- tampering, not a re-scan", seq
                )));
            }
            None => {
                self.received.insert(seq, chunk_payload.to_vec());
            }
        }

        Ok(self.received.len() as u32 == self.total_frames.unwrap())
    }

    pub fn assemble(&self) -> Result<Vec<Vec<u8>>, OpticalReassemblerError> {
        let total = self.total_frames.ok_or_else(|| OpticalReassemblerError::Malformed("no frames received".into()))?;
        if self.received.len() as u32 != total {
            return Err(OpticalReassemblerError::Malformed(format!(
                "incomplete: {} of {} frames received", self.received.len(), total
            )));
        }
        let mut out = Vec::with_capacity(total as usize);
        for seq in 0..total {
            out.push(self.received.get(&seq).unwrap().clone());
        }
        Ok(out)
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
    use std::io::Read;

    #[test]
    fn constructor_rejects_oversized_max_frame_size() {
        match OpticalFrameEncoder::new(QR_MAX_CAPACITY_V40_LOW_REC + 1, 1) {
            Err(OpticalEncoderError::InvalidMaxFrameSize { requested, ceiling }) => {
                assert_eq!(requested, QR_MAX_CAPACITY_V40_LOW_REC + 1);
                assert_eq!(ceiling, QR_MAX_CAPACITY_V40_LOW_REC);
            }
            other => panic!("expected InvalidMaxFrameSize, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn single_frame_encode_decode_round_trip() {
        let payload: Vec<u8> = (0..100u8).collect();
        let chunks = encode_chunks(&payload, 300, None); // 1 chunk
        assert_eq!(chunks.len(), 1);

        let encoder = OpticalFrameEncoder::new(2000, 42).unwrap();
        let frame = encoder.encode_frame(0, 1, &chunks[0]).unwrap();

        let mut r = OpticalFrameReassembler::new();
        let complete = r.ingest_frame(&frame).unwrap();
        assert!(complete);
        let assembled = r.assemble().unwrap();
        assert_eq!(assembled, vec![chunks[0].clone()]);
    }

    #[test]
    fn oversized_chunk_for_frame_size_rejected() {
        let encoder = OpticalFrameEncoder::new(50, 1).unwrap(); // tiny frame budget
        let big_chunk = vec![0u8; 100];
        match encoder.encode_frame(0, 1, &big_chunk) {
            Err(OpticalEncoderError::ChunkTooLargeForMedium { size, max }) => {
                assert_eq!(size, 100 + OPTICAL_FRAME_HEADER_LEN);
                assert_eq!(max, 50);
            }
            other => panic!("expected ChunkTooLargeForMedium, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn bad_magic_rejected() {
        let mut frame = vec![0u8; OPTICAL_FRAME_HEADER_LEN + 10];
        frame[0..4].copy_from_slice(b"XXXX");
        let mut r = OpticalFrameReassembler::new();
        match r.ingest_frame(&frame) {
            Err(OpticalReassemblerError::BadMagic) => {}
            other => panic!("expected BadMagic, got {:?}", other),
        }
    }

    #[test]
    fn session_mismatch_rejected() {
        let payload: Vec<u8> = (0..50u8).collect();
        let chunks = encode_chunks(&payload, 300, None);
        let encoder_a = OpticalFrameEncoder::new(2000, 111).unwrap();
        let encoder_b = OpticalFrameEncoder::new(2000, 222).unwrap();
        let frame_a = encoder_a.encode_frame(0, 1, &chunks[0]).unwrap();
        let frame_b = encoder_b.encode_frame(0, 1, &chunks[0]).unwrap();

        let mut r = OpticalFrameReassembler::new();
        r.ingest_frame(&frame_a).unwrap();
        match r.ingest_frame(&frame_b) {
            Err(OpticalReassemblerError::SessionMismatch { expected, got }) => {
                assert_eq!(expected, 111);
                assert_eq!(got, 222);
            }
            other => panic!("expected SessionMismatch, got {:?}", other),
        }
    }

    #[test]
    fn seq_cross_validation_catches_mismatched_wrapper() {
        let payload: Vec<u8> = (0..50u8).collect();
        let chunks = encode_chunks(&payload, 300, None);
        let encoder = OpticalFrameEncoder::new(2000, 1).unwrap();
        // Deliberately wrap chunk 0 but LABEL it as optical seq 5 --
        // the embedded chunk seq (0) won't match the optical wrapper (5).
        let mismatched_frame = encoder.encode_frame(5, 10, &chunks[0]).unwrap();

        let mut r = OpticalFrameReassembler::new();
        match r.ingest_frame(&mismatched_frame) {
            Err(OpticalReassemblerError::SeqCrossValidationFailed { optical_seq, embedded_chunk_seq }) => {
                assert_eq!(optical_seq, 5);
                assert_eq!(embedded_chunk_seq, 0);
            }
            other => panic!("expected SeqCrossValidationFailed, got {:?}", other),
        }
    }

    #[test]
    fn duplicate_capture_same_content_is_idempotent() {
        let payload: Vec<u8> = (0..50u8).collect();
        let chunks = encode_chunks(&payload, 300, None);
        let encoder = OpticalFrameEncoder::new(2000, 1).unwrap();
        let frame = encoder.encode_frame(0, 1, &chunks[0]).unwrap();

        let mut r = OpticalFrameReassembler::new();
        assert!(r.ingest_frame(&frame).unwrap());
        // Re-scanning the same frame again must NOT error.
        assert!(r.ingest_frame(&frame).unwrap());
    }

    #[test]
    fn duplicate_capture_different_content_rejected_as_tampering() {
        let payload_a: Vec<u8> = (0..50u8).collect();
        let payload_b: Vec<u8> = (50..100u8).collect();
        // Force both to encode as single-chunk, same seq/total, so we can
        // simulate a seq-0 frame with two DIFFERENT bodies.
        let chunks_a = encode_chunks(&payload_a, 300, Some([9u8; 16]));
        let chunks_b = encode_chunks(&payload_b, 300, Some([9u8; 16]));

        let encoder = OpticalFrameEncoder::new(2000, 1).unwrap();
        let frame_a = encoder.encode_frame(0, 1, &chunks_a[0]).unwrap();
        let frame_b = encoder.encode_frame(0, 1, &chunks_b[0]).unwrap();

        let mut r = OpticalFrameReassembler::new();
        r.ingest_frame(&frame_a).unwrap();
        match r.ingest_frame(&frame_b) {
            Err(OpticalReassemblerError::Malformed(msg)) => {
                assert!(msg.contains("tampering"));
            }
            other => panic!("expected Malformed(tampering), got {:?}", other),
        }
    }

    #[test]
    fn shuffled_out_of_order_arrival_still_reassembles_correctly() {
        let payload: Vec<u8> = (0..=255u8).cycle().take(500).collect();
        let chunks = encode_chunks(&payload, 60, None);
        assert!(chunks.len() >= 4, "need multiple chunks for a meaningful shuffle test");

        let encoder = OpticalFrameEncoder::new(2000, 7).unwrap();
        let total = chunks.len() as u32;
        let mut frames: Vec<Vec<u8>> = chunks.iter().enumerate()
            .map(|(i, c)| encoder.encode_frame(i as u32, total, c).unwrap())
            .collect();

        // Reverse the arrival order entirely -- worst-case shuffle.
        frames.reverse();

        let mut r = OpticalFrameReassembler::new();
        let mut complete = false;
        for f in &frames {
            complete = r.ingest_frame(f).unwrap();
        }
        assert!(complete);
        let assembled = r.assemble().unwrap();
        assert_eq!(assembled, chunks, "reversed arrival order produced incorrect reassembly");
    }

    #[test]
    fn full_closed_loop_through_shuffled_and_duplicated_optical_frames() {
        let (box_pk_b, box_sk_b) = generate_box_keypair().unwrap();
        let (sign_pk_a, sign_sk_a) = generate_sign_keypair().unwrap();

        let sender_journal = "optical_closedloop_sender.bin".to_string();
        let receiver_journal = "optical_closedloop_receiver.bin".to_string();
        let _ = std::fs::remove_file(&sender_journal);
        let _ = std::fs::remove_file(&receiver_journal);

        let mut urandom = std::fs::File::open("/dev/urandom").unwrap();
        let mut sender_pad_material = vec![0u8; 300];
        urandom.read_exact(&mut sender_pad_material).unwrap();
        let mut sender_store = PadStore::new(300, &sender_journal, Some(&sender_pad_material), false).unwrap();

        let (_, chunks) = export_pad_payload(&mut sender_store, 80, box_pk_b.as_slice(), &sign_sk_a, 30, None).unwrap();
        assert!(chunks.len() >= 3);

        let encoder = OpticalFrameEncoder::new(2000, 99).unwrap();
        let total = chunks.len() as u32;
        let mut frames: Vec<Vec<u8>> = chunks.iter().enumerate()
            .map(|(i, c)| encoder.encode_frame(i as u32, total, c).unwrap())
            .collect();

        // Simulate real optical capture chaos: shuffle order, and inject
        // duplicate captures of a couple of frames (camera re-scanning).
        let last_idx = frames.len() - 1;
        frames.swap(0, last_idx);
        let dup = frames[1].clone();
        frames.push(dup); // duplicate capture, appended out of place

        let mut r = OpticalFrameReassembler::new();
        let mut complete = false;
        for f in &frames {
            complete = r.ingest_frame(f).unwrap();
        }
        assert!(complete);
        let ordered_chunks = r.assemble().unwrap();

        let mut reassembler = ChunkReassembler::default();
        for c in &ordered_chunks {
            reassembler.ingest(c).unwrap();
        }

        let mut receiver_store = PadStore::new(80, &receiver_journal, None, true).unwrap();
        ingest_assembled_payload(&reassembler, sign_pk_a.as_slice(), &box_pk_b, &box_sk_b, &mut receiver_store).unwrap();

        let (_, received) = receiver_store.reserve(80).unwrap();
        assert_eq!(received, sender_pad_material[0..80],
                   "shuffled+duplicated optical frame round trip corrupted the pad material");

        sender_store.clear();
        receiver_store.clear();
        let _ = std::fs::remove_file(&sender_journal);
        let _ = std::fs::remove_file(&receiver_journal);
    }
}
