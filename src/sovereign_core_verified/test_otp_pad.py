import os, sys, json
from otp_pad import OTPPadStore, OTPExhaustedError

journal = "test_journal.json"
if os.path.exists(journal):
    os.remove(journal)

# fixed pad material so round-trip is checkable against known bytes
pad_material = bytes(range(64))  # 0x00..0x3F, 64 bytes

print("=== TEST 1: encrypt/decrypt round-trip ===")
with OTPPadStore(pad_size=64, journal_path=journal, pad_material=pad_material) as store:
    plaintext = b"HELLO SOVEREIGN MESH NODE ONE"
    offset, ciphertext = store.encrypt(plaintext)
    # simulate receiver: knows offset + has identical pad_material out-of-band
    receiver_pad_slice = pad_material[offset:offset+len(plaintext)]
    recovered = OTPPadStore.decrypt(ciphertext, receiver_pad_slice)
    assert recovered == plaintext, f"MISMATCH: {recovered} != {plaintext}"
    assert ciphertext != plaintext, "ciphertext must not equal plaintext"
    print(f"  offset={offset} remaining={store.remaining()} -- PASS")

print("\n=== TEST 2: exhaustion refusal (no wraparound) ===")
os.remove(journal)
with OTPPadStore(pad_size=16, journal_path=journal, pad_material=bytes(range(16))) as store:
    store.reserve(10)
    try:
        store.reserve(10)  # only 6 remain
        print("  FAIL: should have raised OTPExhaustedError")
        sys.exit(1)
    except OTPExhaustedError as e:
        print(f"  correctly refused over-request: {e}")
    remaining_ok = store.reserve(6)  # exactly what's left
    print(f"  exact remaining reserve succeeded, remaining now={store.remaining()} -- PASS")

print("\n=== TEST 3: NO REUSE across simulated crash + restart ===")
os.remove(journal)
pad64 = bytes(range(64))
# --- process instance 1: reserve 20 bytes, then simulate crash (no clean shutdown) ---
store1 = OTPPadStore(pad_size=64, journal_path=journal, pad_material=pad64)
offset1, bytes1 = store1.reserve(20)
print(f"  instance 1 reserved offset={offset1} len=20")
# simulate abrupt crash: do NOT call store1.clear(), just drop reference
del store1

# --- process instance 2: "restart", must load journal and NOT reissue bytes 0-19 ---
store2 = OTPPadStore(pad_size=64, journal_path=journal, pad_material=pad64)
print(f"  instance 2 loaded consumed_offset={store2._consumed_offset}")
assert store2._consumed_offset == 20, f"journal did not persist correctly: {store2._consumed_offset}"
offset2, bytes2 = store2.reserve(10)
print(f"  instance 2 reserved offset={offset2} len=10")
assert offset2 == 20, f"REUSE BUG: instance 2 issued overlapping offset {offset2}, expected 20"
assert bytes1 != bytes2, "REUSE BUG: identical byte ranges issued to two reservations"
store2.clear()
print("  no overlap between pre-crash and post-restart reservations -- PASS")

print("\n=== TEST 4: two-time-pad check -- encrypting two messages never reuses pad bytes ===")
os.remove(journal)
with OTPPadStore(pad_size=64, journal_path=journal, pad_material=bytes(range(64))) as store:
    off_a, ct_a = store.encrypt(b"MESSAGE ONE")
    off_b, ct_b = store.encrypt(b"MESSAGE TWO")
    range_a = set(range(off_a, off_a + len(ct_a)))
    range_b = set(range(off_b, off_b + len(ct_b)))
    assert range_a.isdisjoint(range_b), f"REUSE BUG: overlapping pad ranges {range_a} & {range_b}"
    print(f"  msg1 range={sorted(range_a)} msg2 range={sorted(range_b)} -- disjoint, PASS")

print("\n=== TEST 5: clear() actually zeroes the buffer ===")
os.remove(journal)
store = OTPPadStore(pad_size=32, journal_path=journal, pad_material=bytes(range(32)))
buf_ref = store._buf
store.clear()
assert all(b == 0 for b in buf_ref), "clear() did not zero the buffer"
print("  buffer zeroed after clear() -- PASS")

os.remove(journal)
print("\nALL OTP PAD TESTS PASSED")
