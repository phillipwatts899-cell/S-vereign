//! file_adapter.rs -- sneakernet-style file-based transport adapter.
//!
//! Writer: each chunk -> temp file -> fsync -> atomic rename, same pattern
//! as pad_store.rs's journal writes. Reader: scans a directory, parses the
//! sequence number out of EACH chunk's own header (not filename, not
//! directory listing order -- read_dir order is explicitly unspecified by
//! POSIX), sorts by that, and fails shut on any gap or duplicate BEFORE
//! handing anything to ChunkReassembler. Hash/signature validation still
//! happens entirely in chunking.rs/transport.rs -- this module only owns
//! filesystem I/O and structural (gap/duplicate) checks.

use crate::chunking::{HEADER_LEN, SESSION_ID_LEN};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

#[derive(Debug)]
pub enum FileAdapterError {
    Io(std::io::Error),
    MalformedChunk(String),
    MissingChunk { expected_seq: u32 },
    DuplicateChunk { seq: u32 },
    NoChunksFound,
}

impl From<std::io::Error> for FileAdapterError {
    fn from(e: std::io::Error) -> Self { FileAdapterError::Io(e) }
}

fn parse_seq(chunk: &[u8]) -> Result<u32, FileAdapterError> {
    if chunk.len() < HEADER_LEN {
        return Err(FileAdapterError::MalformedChunk(
            "file shorter than minimum chunk header length".into(),
        ));
    }
    let off = SESSION_ID_LEN;
    Ok(u32::from_be_bytes(chunk[off..off + 4].try_into().unwrap()))
}

/// Writes each chunk to `dir/chunk_{seq:06}.bin`, atomically (temp file +
/// fsync + rename). Filename uses the chunk's OWN embedded sequence
/// number, not positional index in the input slice -- so even a caller
/// passing chunks out of order produces correctly-named files.
pub fn write_chunks_to_dir(chunks: &[Vec<u8>], dir: &Path) -> Result<(), FileAdapterError> {
    fs::create_dir_all(dir)?;
    for chunk in chunks {
        let seq = parse_seq(chunk)?;
        let final_path = dir.join(format!("chunk_{:06}.bin", seq));
        let tmp_path = dir.join(format!("chunk_{:06}.bin.tmp", seq));
        {
            let mut f = File::create(&tmp_path)?;
            f.write_all(chunk)?;
            f.sync_all()?;
        }
        fs::rename(&tmp_path, &final_path)?; // atomic on POSIX
    }
    Ok(())
}

/// Reads all `*.bin` files from `dir` (explicitly ignoring `*.bin.tmp` --
/// a stray temp file means a writer was interrupted before its rename
/// completed, and must never be treated as valid data), parses each
/// chunk's OWN sequence number from its header, sorts by that (NOT by
/// directory listing order, NOT by filename), and fails shut on any gap
/// or duplicate before returning anything.
pub fn read_chunks_from_dir(dir: &Path) -> Result<Vec<Vec<u8>>, FileAdapterError> {
    let mut entries: Vec<(u32, Vec<u8>)> = Vec::new();

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };
        if !name.ends_with(".bin") {
            continue; // explicitly skips .bin.tmp (interrupted writes) and anything else
        }
        let mut buf = Vec::new();
        File::open(&path)?.read_to_end(&mut buf)?;
        let seq = parse_seq(&buf)?;
        entries.push((seq, buf));
    }

    if entries.is_empty() {
        return Err(FileAdapterError::NoChunksFound);
    }

    entries.sort_by_key(|(seq, _)| *seq);

    // Duplicate check: adjacent equal seqs after sorting.
    for w in entries.windows(2) {
        if w[0].0 == w[1].0 {
            return Err(FileAdapterError::DuplicateChunk { seq: w[0].0 });
        }
    }

    // Gap check: after sorting+dedup-check, seqs must be exactly 0..N contiguous.
    for (i, (seq, _)) in entries.iter().enumerate() {
        if *seq != i as u32 {
            return Err(FileAdapterError::MissingChunk { expected_seq: i as u32 });
        }
    }

    Ok(entries.into_iter().map(|(_, bytes)| bytes).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunking::{encode_chunks, ChunkReassembler};
    use crate::export::export_pad_payload;
    use crate::ingest::ingest_assembled_payload;
    use crate::pad_store::PadStore;
    use crate::transport::{generate_box_keypair, generate_sign_keypair};
    use std::path::PathBuf;

    fn fresh_dir(name: &str) -> PathBuf {
        let p = PathBuf::from(format!("file_adapter_test_{}", name));
        let _ = fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn happy_path_write_then_read_matches_exactly() {
        let dir = fresh_dir("happy");
        let payload: Vec<u8> = (0..200u8).collect();
        let chunks = encode_chunks(&payload, 40, None);

        write_chunks_to_dir(&chunks, &dir).unwrap();
        let read_back = read_chunks_from_dir(&dir).unwrap();

        assert_eq!(read_back.len(), chunks.len());
        // Compare as sets of (seq, bytes) since read order is sorted by
        // seq, which matches encode_chunks' natural order anyway here --
        // but compare content, not assume identical Vec ordering by luck.
        for (original, read) in chunks.iter().zip(read_back.iter()) {
            assert_eq!(original, read);
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn vector_1_atomic_write_integrity_stray_tmp_is_ignored() {
        let dir = fresh_dir("atomic");
        let payload = b"some real payload data here".to_vec();
        let chunks = encode_chunks(&payload, 100, None);
        write_chunks_to_dir(&chunks, &dir).unwrap();

        assert!(!dir.join("chunk_000000.bin.tmp").exists(), "no .tmp file should survive a successful write");

        // Simulate a crash mid-write for a NEW chunk: a .tmp exists, but
        // its corresponding .bin (post-rename) does not.
        let mut f = File::create(dir.join("chunk_000099.bin.tmp")).unwrap();
        f.write_all(b"incomplete garbage, never renamed").unwrap();

        // The reader must completely ignore the stray .tmp -- not error on
        // it, not include it, not treat it as chunk data.
        let read_back = read_chunks_from_dir(&dir).unwrap();
        assert_eq!(read_back.len(), chunks.len(), "reader picked up a stray .tmp file as real data");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn vector_2_missing_chunk_fails_shut_at_reader() {
        let dir = fresh_dir("missing");
        let payload: Vec<u8> = (0..200u8).collect();
        let chunks = encode_chunks(&payload, 40, None);
        write_chunks_to_dir(&chunks, &dir).unwrap();

        fs::remove_file(dir.join("chunk_000002.bin")).unwrap();

        match read_chunks_from_dir(&dir) {
            Err(FileAdapterError::MissingChunk { expected_seq }) => {
                assert_eq!(expected_seq, 2);
            }
            other => panic!("expected MissingChunk, got {:?}", other),
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn vector_3_on_disk_corruption_caught_before_reassembly() {
        let dir = fresh_dir("corrupt");
        let payload: Vec<u8> = (0..200u8).collect();
        let chunks = encode_chunks(&payload, 40, None);
        write_chunks_to_dir(&chunks, &dir).unwrap();

        // Flip a single bit directly in the on-disk file (not in memory).
        let target = dir.join("chunk_000001.bin");
        let mut bytes = fs::read(&target).unwrap();
        bytes[HEADER_LEN + 2] ^= 0x01;
        fs::write(&target, &bytes).unwrap();

        // The file adapter itself doesn't validate hashes -- that's
        // chunking.rs's job. Proving the FULL disk-to-validation path:
        // read succeeds structurally (file adapter has no way to know
        // it's corrupt), but ChunkReassembler.ingest() must reject it.
        let read_back = read_chunks_from_dir(&dir).unwrap();
        let mut reassembler = ChunkReassembler::default();
        let mut caught = false;
        for c in &read_back {
            if reassembler.ingest(c).is_err() {
                caught = true;
                break;
            }
        }
        assert!(caught, "on-disk bit corruption was not caught anywhere in the disk-to-reassembly path");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn vector_4_filename_sorting_independence() {
        let dir = fresh_dir("sortorder");
        let payload: Vec<u8> = (0..200u8).collect();
        let chunks = encode_chunks(&payload, 40, None);

        // Write chunks in REVERSE order and under filenames that would
        // sort incorrectly if we trusted filename/directory order instead
        // of the header's embedded sequence number.
        fs::create_dir_all(&dir).unwrap();
        for (i, chunk) in chunks.iter().enumerate().rev() {
            // Deliberately misleading filename -- reader must ignore this
            // and use the embedded header seq instead.
            let misleading_name = format!("zzz_reverse_write_order_{}.bin", chunks.len() - i);
            fs::write(dir.join(&misleading_name), chunk).unwrap();
        }

        let read_back = read_chunks_from_dir(&dir).unwrap();
        // Confirm correct ascending order by embedded seq, regardless of
        // the misleading filenames or reverse write order.
        for (i, c) in read_back.iter().enumerate() {
            let seq = parse_seq(c).unwrap();
            assert_eq!(seq, i as u32, "chunk at position {} has wrong embedded seq {}", i, seq);
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn vector_5_duplicate_injection_rejected() {
        let dir = fresh_dir("duplicate");
        let payload: Vec<u8> = (0..200u8).collect();
        let chunks = encode_chunks(&payload, 40, None);
        write_chunks_to_dir(&chunks, &dir).unwrap();

        // Inject an identical copy of chunk 1 under a malformed/different name.
        let original = fs::read(dir.join("chunk_000001.bin")).unwrap();
        fs::write(dir.join("chunk_000001_evil_copy.bin"), &original).unwrap();

        match read_chunks_from_dir(&dir) {
            Err(FileAdapterError::DuplicateChunk { seq }) => {
                assert_eq!(seq, 1);
            }
            other => panic!("expected DuplicateChunk, got {:?}", other),
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn full_closed_loop_through_actual_disk_files() {
        let dir = fresh_dir("closedloop");
        let sender_journal = "file_adapter_closedloop_sender.bin".to_string();
        let receiver_journal = "file_adapter_closedloop_receiver.bin".to_string();
        let _ = fs::remove_file(&sender_journal);
        let _ = fs::remove_file(&receiver_journal);

        let (box_pk_b, box_sk_b) = generate_box_keypair().unwrap();
        let (sign_pk_a, sign_sk_a) = generate_sign_keypair().unwrap();

        let mut urandom = File::open("/dev/urandom").unwrap();
        let mut sender_pad_material = vec![0u8; 256];
        urandom.read_exact(&mut sender_pad_material).unwrap();
        let mut sender_store = PadStore::new(256, &sender_journal, Some(&sender_pad_material), false).unwrap();

        let (_, chunks) = export_pad_payload(&mut sender_store, 64, box_pk_b.as_slice(), &sign_sk_a, 40, None).unwrap();

        // Genuinely round-trip through the filesystem, not an in-memory Vec.
        write_chunks_to_dir(&chunks, &dir).unwrap();
        let chunks_from_disk = read_chunks_from_dir(&dir).unwrap();

        let mut reassembler = ChunkReassembler::default();
        for c in &chunks_from_disk {
            reassembler.ingest(c).unwrap();
        }

        let mut receiver_store = PadStore::new(64, &receiver_journal, None, true).unwrap();
        ingest_assembled_payload(&reassembler, sign_pk_a.as_slice(), &box_pk_b, &box_sk_b, &mut receiver_store).unwrap();

        let (_, received) = receiver_store.reserve(64).unwrap();
        assert_eq!(received, sender_pad_material[0..64], "disk round-trip corrupted the pad material");

        sender_store.clear();
        receiver_store.clear();
        fs::remove_dir_all(&dir).ok();
        let _ = fs::remove_file(&sender_journal);
        let _ = fs::remove_file(&receiver_journal);
    }
}
