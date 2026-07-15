"""
otp_chunking.py -- Phase 2: transport-agnostic chunking/sequencing.

Operates on the OUTPUT of sign_and_wrap() -- signed ciphertext, which is
not secret (confidentiality already comes from crypto_box_seal in Phase 1;
authenticity already comes from the Ed25519 signature in Phase 1b, verified
AFTER reassembly). This layer adds no new cryptographic authentication
boundary. What it adds:
  1. Fail-fast corruption/injection detection per chunk (unkeyed BLAKE2b --
     catches transmission bit-errors and malformed injected chunks early,
     rather than only discovering a problem after full reassembly).
  2. Strict in-order, single-session delivery enforcement -- rejects
     out-of-order chunks, session-id mismatches (stitching two different
     transmissions together), and duplicate/replayed sequence numbers.
  3. A bound on total_chunks to prevent a forged header from causing
     unbounded memory allocation (DoS resistance), not confidentiality.
"""
import struct
import nacl.bindings

SESSION_ID_LEN = 16
SEQ_LEN = 4
TOTAL_LEN = 4
PAYLOAD_LEN_LEN = 4
CHUNK_HASH_LEN = 32
HEADER_LEN = SESSION_ID_LEN + SEQ_LEN + TOTAL_LEN + PAYLOAD_LEN_LEN

DEFAULT_MAX_TOTAL_CHUNKS = 100_000


class ChunkFormatError(Exception):
    pass


class SequenceViolationError(Exception):
    pass


def _chunk_hash(header_and_payload: bytes) -> bytes:
    return nacl.bindings.crypto_generichash_blake2b_salt_personal(
        header_and_payload, digest_size=CHUNK_HASH_LEN, person=b"otp_chunk_hash__"[:16]
    )


def encode_chunks(payload: bytes, chunk_payload_size: int = 200, session_id: bytes = None):
    """Yields raw chunk bytes: header || payload_slice || chunk_hash.
    payload is signed ciphertext -- not secret, ordinary bytes are fine."""
    if session_id is None:
        import os
        session_id = os.urandom(SESSION_ID_LEN)
    if len(session_id) != SESSION_ID_LEN:
        raise ValueError(f"session_id must be {SESSION_ID_LEN} bytes")
    if chunk_payload_size <= 0:
        raise ValueError("chunk_payload_size must be positive")

    total_chunks = max(1, (len(payload) + chunk_payload_size - 1) // chunk_payload_size)
    for seq in range(total_chunks):
        start = seq * chunk_payload_size
        chunk_payload = payload[start:start + chunk_payload_size]
        header = (
            session_id
            + struct.pack(">I", seq)
            + struct.pack(">I", total_chunks)
            + struct.pack(">I", len(chunk_payload))
        )
        h = _chunk_hash(header + chunk_payload)
        yield header + chunk_payload + h


class ChunkReassembler:
    """Strict in-order, single-session chunk reassembly with fail-fast
    corruption/injection detection. Does NOT itself authenticate the
    sender -- that check happens after assemble(), via
    otp_transport.verify_and_unwrap() on the reassembled bytes."""

    def __init__(self, max_total_chunks: int = DEFAULT_MAX_TOTAL_CHUNKS):
        self.max_total_chunks = max_total_chunks
        self.session_id = None
        self.total_chunks = None
        self._received = {}
        self.next_expected_seq = 0

    def ingest(self, raw_chunk: bytes) -> bool:
        """Returns True once the full sequence has been received.
        Raises ChunkFormatError on corruption/malformed input, or
        SequenceViolationError on out-of-order/mismatched-session/
        duplicate/replayed chunks."""
        if len(raw_chunk) < HEADER_LEN + CHUNK_HASH_LEN:
            raise ChunkFormatError("chunk shorter than minimum header+hash length")

        session_id = raw_chunk[:SESSION_ID_LEN]
        off = SESSION_ID_LEN
        seq = struct.unpack(">I", raw_chunk[off:off+SEQ_LEN])[0]; off += SEQ_LEN
        total = struct.unpack(">I", raw_chunk[off:off+TOTAL_LEN])[0]; off += TOTAL_LEN
        payload_len = struct.unpack(">I", raw_chunk[off:off+PAYLOAD_LEN_LEN])[0]; off += PAYLOAD_LEN_LEN

        expected_total_len = HEADER_LEN + payload_len + CHUNK_HASH_LEN
        if len(raw_chunk) != expected_total_len:
            raise ChunkFormatError(
                f"declared payload_len {payload_len} doesn't match actual chunk length"
            )

        payload = raw_chunk[off:off+payload_len]
        received_hash = raw_chunk[off+payload_len:off+payload_len+CHUNK_HASH_LEN]
        header = raw_chunk[:HEADER_LEN]
        expected_hash = _chunk_hash(header + payload)

        import hmac as _hmac_module
        if not _hmac_module.compare_digest(expected_hash, received_hash):
            raise ChunkFormatError("chunk hash mismatch -- corrupted or forged chunk")

        if total <= 0 or total > self.max_total_chunks:
            raise ChunkFormatError(
                f"declared total_chunks {total} outside sane bound (1..{self.max_total_chunks})"
            )

        if self.session_id is None:
            # First chunk of a new sequence -- learn session_id and total_chunks.
            self.session_id = session_id
            self.total_chunks = total
        else:
            if session_id != self.session_id:
                raise SequenceViolationError(
                    "session_id mismatch -- possible attempt to stitch chunks "
                    "from two different transmissions together"
                )
            if total != self.total_chunks:
                raise SequenceViolationError("total_chunks changed mid-stream")

        if seq != self.next_expected_seq:
            raise SequenceViolationError(
                f"out-of-order or duplicate/replayed chunk: expected seq "
                f"{self.next_expected_seq}, got {seq}"
            )

        self._received[seq] = payload
        self.next_expected_seq += 1
        return self.next_expected_seq == self.total_chunks

    def assemble(self) -> bytes:
        if self.total_chunks is None or self.next_expected_seq != self.total_chunks:
            raise ChunkFormatError(
                f"incomplete sequence: received {self.next_expected_seq} of "
                f"{self.total_chunks!r} expected chunks"
            )
        return b"".join(self._received[i] for i in range(self.total_chunks))
