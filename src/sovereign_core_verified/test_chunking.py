import sys
from sovereign_memory import SecureKeyBuffer
from otp_transport import (
    generate_box_keypair, seal_pad, open_sealed,
    generate_sign_keypair, sign_and_wrap, verify_and_unwrap,
)
from otp_chunking import encode_chunks, ChunkReassembler, ChunkFormatError, SequenceViolationError

print("=== TEST 1: FULL END-TO-END -- seal, sign, chunk, reassemble, verify, unwrap, decrypt ===")
box_pk_b, box_sk_b = generate_box_keypair()
sign_pk_a, sign_sk_a = generate_sign_keypair()
sign_pk_a_bytes = bytes(sign_pk_a.expose_raw_view())
box_pk_b_bytes = bytes(box_pk_b.expose_raw_view())

plaintext = b"REAL OTP PAD SEGMENT: " + bytes(range(256))  # bigger than one chunk
with SecureKeyBuffer(len(plaintext)) as pt_buf:
    pt_buf.write_at_offset(plaintext)
    ciphertext = seal_pad(pt_buf, len(plaintext), box_pk_b_bytes)
signed_ct = sign_and_wrap(ciphertext, sign_sk_a)

chunks = list(encode_chunks(signed_ct, chunk_payload_size=64))
print(f"  {len(signed_ct)} byte signed ciphertext -> {len(chunks)} chunks")
assert len(chunks) > 1, "test needs multiple chunks to be meaningful"

reassembler = ChunkReassembler()
complete = False
for c in chunks:
    complete = reassembler.ingest(c)
assert complete
reassembled = reassembler.assemble()
assert reassembled == signed_ct, "reassembled bytes don't match original signed_ciphertext"

recovered_ct = verify_and_unwrap(reassembled, sign_pk_a_bytes)
with SecureKeyBuffer(len(plaintext)) as out_buf:
    n = open_sealed(recovered_ct, box_pk_b, box_sk_b, out_buf)
    recovered_pt = bytes(out_buf.expose_raw_view())[:n]
    assert recovered_pt == plaintext
print("  full chain seal->sign->chunk->reassemble->verify->unwrap->decrypt -- exact match, PASS")

print("\n=== TEST 2: TRUNCATION -- drop the last chunk, receiver must detect incompleteness ===")
r2 = ChunkReassembler()
for c in chunks[:-1]:
    result = r2.ingest(c)
    assert result == False, "reassembler falsely reported completeness before all chunks arrived"
try:
    r2.assemble()
    print("  FAIL: assemble() succeeded on an incomplete sequence")
    sys.exit(1)
except ChunkFormatError as e:
    print(f"  correctly detected truncated/incomplete sequence: {e}")

print("\n=== TEST 3: REORDERING -- out-of-order chunk fails shut immediately ===")
r3 = ChunkReassembler()
r3.ingest(chunks[0])
try:
    r3.ingest(chunks[2])  # skip chunk[1], feed chunk[2] out of order
    print("  FAIL: out-of-order chunk was accepted")
    sys.exit(1)
except SequenceViolationError as e:
    print(f"  correctly rejected out-of-order chunk immediately: {e}")

print("\n=== TEST 4: SESSION STITCHING -- injecting a chunk from a DIFFERENT session fails shut ===")
other_signed_ct = sign_and_wrap(b"UNRELATED SECOND MESSAGE PAYLOAD", sign_sk_a)
other_chunks = list(encode_chunks(other_signed_ct, chunk_payload_size=64, session_id=b"X" * 16))
r4 = ChunkReassembler()
r4.ingest(chunks[0])
try:
    r4.ingest(other_chunks[0])  # different session_id entirely
    print("  FAIL: cross-session chunk was accepted -- stitching attack succeeded")
    sys.exit(1)
except SequenceViolationError as e:
    print(f"  correctly rejected cross-session chunk (stitching attack defeated): {e}")

print("\n=== TEST 5: CORRUPTION -- flipped bit inside a chunk's payload fails shut ===")
from otp_chunking import HEADER_LEN
tampered = bytearray(chunks[1])
tamper_offset = HEADER_LEN + 2  # inside the payload region, not the header
tampered[tamper_offset] ^= 0xFF
r5 = ChunkReassembler()
r5.ingest(chunks[0])
try:
    r5.ingest(bytes(tampered))
    print("  FAIL: corrupted chunk was accepted")
    sys.exit(1)
except ChunkFormatError as e:
    print(f"  correctly rejected corrupted chunk (hash mismatch): {e}")

print("\n=== TEST 6: DUPLICATE / REPLAY -- resending an already-consumed sequence number fails shut ===")
r6 = ChunkReassembler()
r6.ingest(chunks[0])
r6.ingest(chunks[1])
try:
    r6.ingest(chunks[0])  # replay chunk 0 after it's already been consumed
    print("  FAIL: replayed chunk was accepted")
    sys.exit(1)
except SequenceViolationError as e:
    print(f"  correctly rejected replayed/duplicate chunk: {e}")

print("\n=== TEST 7: DoS -- forged astronomical total_chunks is rejected by the BOUND CHECK specifically ===")
import struct
from otp_chunking import _chunk_hash, HEADER_LEN, CHUNK_HASH_LEN

# Build a chunk with a forged total_chunks value FROM SCRATCH, with a
# correctly-recomputed hash over the forged header -- so the hash check
# passes and we isolate whether the total_chunks bound check itself catches it.
c0 = chunks[0]
payload0 = c0[HEADER_LEN:-CHUNK_HASH_LEN]
forged_header = c0[:16] + struct.pack(">I", 0) + struct.pack(">I", 4_000_000_000) + struct.pack(">I", len(payload0))
forged_hash = _chunk_hash(forged_header + payload0)
forged_chunk = forged_header + payload0 + forged_hash

r7 = ChunkReassembler()
try:
    r7.ingest(forged_chunk)
    print("  FAIL: forged huge total_chunks (with a VALID hash) was accepted")
    sys.exit(1)
except ChunkFormatError as e:
    assert "outside sane bound" in str(e), f"rejected for the wrong reason: {e}"
    print(f"  correctly rejected by the total_chunks bound check specifically: {e}")

for buf in [box_pk_b, box_sk_b, sign_pk_a, sign_sk_a]:
    buf.clear()

print("\nALL CHUNKING TESTS PASSED")
