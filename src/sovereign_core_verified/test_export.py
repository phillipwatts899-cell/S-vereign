import os, sys
from otp_pad import OTPPadStore, OTPExhaustedError
from otp_transport import generate_box_keypair, generate_sign_keypair
from otp_export import export_pad_payload
from otp_chunking import ChunkReassembler
from otp_ingest import ingest_assembled_payload, IngestionAbortedError

def fresh_journal(name):
    p = f"export_{name}.json"
    if os.path.exists(p):
        os.remove(p)
    return p

box_pk_recipient, box_sk_recipient = generate_box_keypair()
sign_pk_sender, sign_sk_sender = generate_sign_keypair()
box_pk_recipient_bytes = bytes(box_pk_recipient.expose_raw_view())
sign_pk_sender_bytes = bytes(sign_pk_sender.expose_raw_view())

print("=== TEST 1: FULL CLOSED LOOP -- sender export -> chunks -> receiver ingest, exact byte match ===")
sender_journal = fresh_journal("sender")
receiver_journal = fresh_journal("receiver")

sender_pad_material = os.urandom(256)
sender_store = OTPPadStore(pad_size=256, journal_path=sender_journal, pad_material=sender_pad_material)

src_offset, chunks = export_pad_payload(
    sender_store, n=64, recipient_box_pk=box_pk_recipient_bytes,
    sender_sign_sk=sign_sk_sender, chunk_payload_size=40
)
print(f"  exported 64 bytes starting at source offset {src_offset}, produced {len(chunks)} chunks")
assert src_offset == 0

reassembler = ChunkReassembler()
for c in chunks:
    reassembler.ingest(c)

receiver_store = ingest_assembled_payload(
    reassembler, sign_pk_sender_bytes, box_pk_recipient, box_sk_recipient,
    pad_size=64, journal_path=receiver_journal
)
off_r, received_bytes = receiver_store.reserve(64)
expected = sender_pad_material[0:64]
assert received_bytes == expected, "receiver's pad material doesn't match what sender actually burned"
print("  receiver's pad material EXACTLY matches sender's burned slice -- closed loop verified, PASS")
sender_store.clear()
receiver_store.clear()

print("\n=== TEST 2: ATOMIC LOCAL CONSUMPTION -- journal advances regardless of transmission outcome ===")
sender_journal2 = fresh_journal("atomic")
pad_material_2 = os.urandom(128)
sender_store2 = OTPPadStore(pad_size=128, journal_path=sender_journal2, pad_material=pad_material_2)
assert sender_store2.remaining() == 128

_, chunks2 = export_pad_payload(sender_store2, n=30, recipient_box_pk=box_pk_recipient_bytes,
                                  sender_sign_sk=sign_sk_sender, chunk_payload_size=100)
assert sender_store2.remaining() == 98, f"expected 98 remaining, got {sender_store2.remaining()}"
del sender_store2

sender_store2_reloaded = OTPPadStore(pad_size=128, journal_path=sender_journal2, pad_material=pad_material_2)
assert sender_store2_reloaded.remaining() == 98, (
    f"journal did not persist the export's consumption across restart: "
    f"remaining={sender_store2_reloaded.remaining()}, expected 98"
)
print("  pad bytes remained burned after restart even though the resulting chunks were never used -- PASS")
print("  (this is the correct, deliberate OTP property: 'maybe sent, definitely burned' beats reuse risk)")
sender_store2_reloaded.clear()

print("\n=== TEST 3: EXHAUSTION -- over-request fails BEFORE burning anything ===")
sender_journal3 = fresh_journal("exhaust")
pad_material_3 = os.urandom(16)
sender_store3 = OTPPadStore(pad_size=16, journal_path=sender_journal3, pad_material=pad_material_3)
try:
    export_pad_payload(sender_store3, n=100, recipient_box_pk=box_pk_recipient_bytes,
                        sender_sign_sk=sign_sk_sender, chunk_payload_size=40)
    print("  FAIL: over-request export was accepted")
    sys.exit(1)
except OTPExhaustedError as e:
    assert sender_store3.remaining() == 16, "exhaustion failure still burned pad bytes -- should not have"
    print(f"  correctly refused, zero bytes burned on failure: {e}")
sender_store3.clear()

print("\n=== TEST 4: chunks are genuinely transport-ready -- correct count, correct reassembly ===")
sender_journal4 = fresh_journal("chunks")
pad_material_4 = os.urandom(500)
sender_store4 = OTPPadStore(pad_size=500, journal_path=sender_journal4, pad_material=pad_material_4)
_, chunks4 = export_pad_payload(sender_store4, n=300, recipient_box_pk=box_pk_recipient_bytes,
                                  sender_sign_sk=sign_sk_sender, chunk_payload_size=50)
assert len(chunks4) >= 7
r4 = ChunkReassembler()
completed = False
for c in chunks4:
    completed = r4.ingest(c)
assert completed
print(f"  {len(chunks4)} chunks produced from a 300-byte export, reassemble to completion cleanly -- PASS")
sender_store4.clear()

for j in ["export_sender.json", "export_receiver.json", "export_atomic.json",
          "export_exhaust.json", "export_chunks.json"]:
    if os.path.exists(j):
        os.remove(j)

print("\nALL EXPORT TESTS PASSED")
