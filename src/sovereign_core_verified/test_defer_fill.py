import os, sys
from otp_pad import OTPPadStore, CorruptJournalException
from nacl._sodium import lib as _sodium_lib

journal = "defer_fill_journal.json"
if os.path.exists(journal):
    os.remove(journal)

print("=== TEST 1: defer_fill + external population + finalize_fill works ===")
store = OTPPadStore(pad_size=32, journal_path=journal, defer_fill=True)
assert not os.path.exists(journal), "journal must not exist before finalize_fill()"
# simulate external population, e.g. via open_sealed writing to store.addr
_sodium_lib.randombytes(store.addr, store.size)
before = bytes(store._buf)
store.finalize_fill()
assert os.path.exists(journal), "journal should exist immediately after finalize_fill()"
off, pad = store.reserve(10)
assert off == 0 and len(pad) == 10
print("  populate -> finalize_fill -> reserve() all work, journal created only after finalize -- PASS")
store.clear()

print("\n=== TEST 2: abandoned defer_fill (finalize_fill never called) creates NO journal ===")
os.remove(journal)
store2 = OTPPadStore(pad_size=32, journal_path=journal, defer_fill=True)
_sodium_lib.randombytes(store2.addr, store2.size)
# simulate a pipeline failure AFTER population but BEFORE finalize_fill --
# caller should clear() and never call finalize_fill()
store2.clear()
assert not os.path.exists(journal), "journal must NOT exist -- finalize_fill was never called"
print("  abandoned pre-finalize store created zero persistent state -- PASS")

print("\n=== TEST 3: reserve()/remaining() refuse to run before finalize_fill ===")
store3 = OTPPadStore(pad_size=32, journal_path=journal, defer_fill=True)
try:
    store3.reserve(5)
    print("  FAIL: reserve() succeeded on an unfinalized store")
    sys.exit(1)
except RuntimeError as e:
    print(f"  correctly refused reserve() before finalize_fill: {e}")
try:
    store3.remaining()
    print("  FAIL: remaining() succeeded on an unfinalized store")
    sys.exit(1)
except RuntimeError as e:
    print(f"  correctly refused remaining() before finalize_fill: {e}")
store3.clear()

print("\n=== TEST 4: defer_fill=True + pad_material given simultaneously is rejected ===")
try:
    OTPPadStore(pad_size=32, journal_path=journal, defer_fill=True, pad_material=b"X"*32)
    print("  FAIL: conflicting defer_fill + pad_material was accepted")
    sys.exit(1)
except ValueError as e:
    print(f"  correctly rejected conflicting construction args: {e}")

print("\n=== TEST 5: finalize_fill() called twice is rejected ===")
if os.path.exists(journal):
    os.remove(journal)
store5 = OTPPadStore(pad_size=32, journal_path=journal, defer_fill=True)
_sodium_lib.randombytes(store5.addr, store5.size)
store5.finalize_fill()
try:
    store5.finalize_fill()
    print("  FAIL: double finalize_fill() was accepted")
    sys.exit(1)
except RuntimeError as e:
    print(f"  correctly rejected double finalize_fill(): {e}")
store5.clear()

if os.path.exists(journal):
    os.remove(journal)
print("\nALL DEFER_FILL TESTS PASSED")
