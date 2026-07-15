import os, sys
from otp_pad import OTPPadStore, OTPExhaustedError
from nacl._sodium import ffi as _sodium_ffi

def fresh_journal(name):
    p = f"reserve_into_{name}.json"
    if os.path.exists(p):
        os.remove(p)
    return p

print("=== TEST 1: reserve_into copies correct bytes to correct destination offset ===")
journal = fresh_journal("basic")
pad_material = bytes(range(64))
store = OTPPadStore(pad_size=64, journal_path=journal, pad_material=pad_material)
dest = bytearray(20)
dest_addr = _sodium_ffi.from_buffer(dest)
offset = store.reserve_into(10, dest_addr, dest_offset=4)
assert offset == 0, f"expected source offset 0, got {offset}"
assert list(dest[4:14]) == list(pad_material[0:10]), "copied bytes don't match expected pad slice"
assert list(dest[0:4]) == [0,0,0,0], "bytes before dest_offset were touched"
assert list(dest[14:20]) == [0,0,0,0,0,0], "bytes after the copy were touched"
print(f"  correct bytes at correct offset, no bleed into adjacent dest memory -- PASS")
store.clear()

print("\n=== TEST 2: sequential reserve_into calls advance correctly, no overlap ===")
journal2 = fresh_journal("sequential")
store2 = OTPPadStore(pad_size=64, journal_path=journal2, pad_material=pad_material)
dest2 = bytearray(30)
dest2_addr = _sodium_ffi.from_buffer(dest2)
off_a = store2.reserve_into(10, dest2_addr, dest_offset=0)
off_b = store2.reserve_into(10, dest2_addr, dest_offset=10)
assert off_a == 0 and off_b == 10
assert list(dest2[0:10]) == list(pad_material[0:10])
assert list(dest2[10:20]) == list(pad_material[10:20])
print("  two sequential reservations land at correct, non-overlapping source AND dest offsets -- PASS")
store2.clear()

print("\n=== TEST 3: exhaustion refusal matches reserve()'s behavior ===")
journal3 = fresh_journal("exhaust")
store3 = OTPPadStore(pad_size=16, journal_path=journal3, pad_material=bytes(range(16)))
dest3 = bytearray(20)
dest3_addr = _sodium_ffi.from_buffer(dest3)
store3.reserve_into(10, dest3_addr)
try:
    store3.reserve_into(10, dest3_addr, dest_offset=10)  # only 6 remain
    print("  FAIL: over-request was accepted")
    sys.exit(1)
except OTPExhaustedError as e:
    print(f"  correctly refused over-request: {e}")
store3.clear()

print("\n=== TEST 4: reserve() and reserve_into() interleave correctly on the SAME store (shared offset state) ===")
journal4 = fresh_journal("interleave")
store4 = OTPPadStore(pad_size=64, journal_path=journal4, pad_material=pad_material)
off1, bytes1 = store4.reserve(10)          # bytes-returning path
dest4 = bytearray(10)
dest4_addr = _sodium_ffi.from_buffer(dest4)
off2 = store4.reserve_into(10, dest4_addr)  # zero-copy path, same store
assert off1 == 0 and off2 == 10, "reserve() and reserve_into() didn't share consistent offset state"
assert bytes1 == pad_material[0:10]
assert bytes(dest4) == pad_material[10:20]
print("  reserve() and reserve_into() correctly share the same offset counter -- PASS")
store4.clear()

print("\n=== TEST 5: NO REUSE across crash+restart still holds for reserve_into ===")
journal5 = fresh_journal("crash")
store5a = OTPPadStore(pad_size=64, journal_path=journal5, pad_material=pad_material)
dest5 = bytearray(20)
dest5_addr = _sodium_ffi.from_buffer(dest5)
off_before_crash = store5a.reserve_into(20, dest5_addr)
del store5a  # simulate crash, no clean shutdown
store5b = OTPPadStore(pad_size=64, journal_path=journal5, pad_material=pad_material)
assert store5b._consumed_offset == 20, f"journal did not persist reserve_into's advance: {store5b._consumed_offset}"
off_after_restart = store5b.reserve_into(5, dest5_addr)
assert off_after_restart == 20, f"REUSE BUG: post-restart offset {off_after_restart}, expected 20"
print("  reserve_into's journal advance survives crash+restart, no reuse -- PASS")
store5b.clear()

print("\n=== TEST 6: refuses to run before finalize_fill (defer_fill store) ===")
journal6 = fresh_journal("unfinalized")
store6 = OTPPadStore(pad_size=32, journal_path=journal6, defer_fill=True)
dest6 = bytearray(10)
dest6_addr = _sodium_ffi.from_buffer(dest6)
try:
    store6.reserve_into(10, dest6_addr)
    print("  FAIL: reserve_into succeeded on an unfinalized store")
    sys.exit(1)
except RuntimeError as e:
    print(f"  correctly refused: {e}")
store6.clear()

for j in ["reserve_into_basic.json", "reserve_into_sequential.json", "reserve_into_exhaust.json",
          "reserve_into_interleave.json", "reserve_into_crash.json"]:
    if os.path.exists(j):
        os.remove(j)

print("\nALL RESERVE_INTO TESTS PASSED")
