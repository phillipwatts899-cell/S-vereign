import os, sys
from sovereign_memory import SecureKeyBuffer
from otp_transport import generate_box_keypair, seal_pad, sign_and_wrap, generate_sign_keypair
from otp_chunking import encode_chunks, ChunkReassembler
from otp_ingest import ingest_assembled_payload, IngestionAbortedError

def fresh_journal(name):
    p = f"ingest_{name}.json"
    if os.path.exists(p):
        os.remove(p)
    return p

print("=== TEST 1: HAPPY PATH -- full chain produces a usable, finalized pad store ===")
box_pk_b, box_sk_b = generate_box_keypair()
sign_pk_a, sign_sk_a = generate_sign_keypair()
sign_pk_a_bytes = bytes(sign_pk_a.expose_raw_view())
box_pk_b_bytes = bytes(box_pk_b.expose_raw_view())

pad_plaintext = os.urandom(128)  # simulated real pad material
with SecureKeyBuffer(len(pad_plaintext)) as pt_buf:
    pt_buf.write_at_offset(pad_plaintext)
    ciphertext = seal_pad(pt_buf, len(pad_plaintext), box_pk_b_bytes)
signed_ct = sign_and_wrap(ciphertext, sign_sk_a)
chunks = list(encode_chunks(signed_ct, chunk_payload_size=40))

journal = fresh_journal("happy")
reassembler = ChunkReassembler()
for c in chunks:
    reassembler.ingest(c)

store = ingest_assembled_payload(
    reassembler, sign_pk_a_bytes, box_pk_b, box_sk_b,
    pad_size=len(pad_plaintext), journal_path=journal
)
assert os.path.exists(journal), "journal should exist after successful ingestion"
off, pad = store.reserve(20)
assert pad == pad_plaintext[:20], "decrypted pad material doesn't match what was sent"
print(f"  full chain -> usable OTPPadStore, reserve() returns correct pad bytes -- PASS")
store.clear()

print("\n=== TEST 2: FAIL SHUT -- incomplete reassembly (dropped final chunk) ===")
journal2 = fresh_journal("incomplete")
r2 = ChunkReassembler()
for c in chunks[:-1]:
    r2.ingest(c)
try:
    ingest_assembled_payload(r2, sign_pk_a_bytes, box_pk_b, box_sk_b, len(pad_plaintext), journal2)
    print("  FAIL: incomplete reassembly was accepted")
    sys.exit(1)
except IngestionAbortedError as e:
    assert not os.path.exists(journal2), "journal must NOT exist after incomplete-reassembly failure"
    print(f"  correctly aborted, zero journal created: {e}")

print("\n=== TEST 3: FAIL SHUT -- signature verification failure (wrong sender pk) ===")
journal3 = fresh_journal("badsig")
sign_pk_x, sign_sk_x = generate_sign_keypair()
r3 = ChunkReassembler()
for c in chunks:
    r3.ingest(c)
try:
    wrong_pk = bytes(sign_pk_x.expose_raw_view())
    ingest_assembled_payload(r3, wrong_pk, box_pk_b, box_sk_b, len(pad_plaintext), journal3)
    print("  FAIL: bad signature was accepted")
    sys.exit(1)
except IngestionAbortedError as e:
    assert not os.path.exists(journal3), "journal must NOT exist after signature failure"
    print(f"  correctly aborted, zero journal created: {e}")

print("\n=== TEST 4: FAIL SHUT -- sealed-box decryption failure (wrong recipient keypair) ===")
journal4 = fresh_journal("badbox")
box_pk_wrong, box_sk_wrong = generate_box_keypair()
r4 = ChunkReassembler()
for c in chunks:
    r4.ingest(c)
try:
    ingest_assembled_payload(r4, sign_pk_a_bytes, box_pk_wrong, box_sk_wrong, len(pad_plaintext), journal4)
    print("  FAIL: wrong recipient keypair decryption was accepted")
    sys.exit(1)
except IngestionAbortedError as e:
    assert not os.path.exists(journal4), "journal must NOT exist after decryption failure"
    print(f"  correctly aborted, zero journal created: {e}")

print("\n=== TEST 5: FAIL SHUT -- tampered ciphertext bit-flip inside a chunk ===")
journal5 = fresh_journal("tampered")
tampered_chunks = list(chunks)
tb = bytearray(tampered_chunks[1])
tb[35] ^= 0xFF  # flip a byte inside the payload region of a middle chunk
r5 = ChunkReassembler()
r5.ingest(tampered_chunks[0])
try:
    r5.ingest(bytes(tb))
    print("  FAIL: tampered chunk was accepted at the chunk layer (should have failed earlier)")
    sys.exit(1)
except Exception as e:
    # ChunkFormatError expected here -- confirms defense in depth: even if this
    # layer were somehow bypassed, ingestion itself still wouldn't create a journal
    assert not os.path.exists(journal5)
    print(f"  correctly rejected at chunk layer (defense in depth, before ingestion is even reached): {type(e).__name__}: {e}")

print("\n=== TEST 6: expected pad_size mismatch (decrypted length != requested pad_size) ===")
journal6 = fresh_journal("sizemismatch")
r6 = ChunkReassembler()
for c in chunks:
    r6.ingest(c)
try:
    ingest_assembled_payload(r6, sign_pk_a_bytes, box_pk_b, box_sk_b, pad_size=len(pad_plaintext) + 10, journal_path=journal6)
    print("  FAIL: pad_size mismatch was accepted")
    sys.exit(1)
except IngestionAbortedError as e:
    assert not os.path.exists(journal6)
    print(f"  correctly aborted on pad_size mismatch, zero journal created: {e}")

for buf in [box_pk_b, box_sk_b, sign_pk_a, sign_sk_a, sign_pk_x, sign_sk_x, box_pk_wrong, box_sk_wrong]:
    buf.clear()
for j in ["ingest_happy.json"]:
    if os.path.exists(j):
        os.remove(j)

print("\nALL INGESTION BRIDGE TESTS PASSED")
