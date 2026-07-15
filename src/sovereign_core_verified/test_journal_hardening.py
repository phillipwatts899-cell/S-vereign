import os, sys, json
from otp_pad import OTPPadStore, CorruptJournalException

journal = "hardening_journal.json"

def reset():
    if os.path.exists(journal):
        os.remove(journal)

pad_material = bytes(range(64))

print("=== TEST A: legitimate first run, no journal file exists ===")
reset()
with OTPPadStore(pad_size=64, journal_path=journal, pad_material=pad_material) as store:
    assert store._consumed_offset == 0
    store.reserve(10)
print("  fresh journal created, offset=0 -> 10 -- PASS")

print("\n=== TEST B: tampered offset (rolled backward) is REJECTED ===")
with open(journal, "r") as f:
    data = json.load(f)
print(f"  legit journal before tamper: {data}")
data["consumed_offset"] = 0   # attacker rolls the offset back to reuse bytes 0-9
with open(journal, "w") as f:
    json.dump(data, f)
try:
    OTPPadStore(pad_size=64, journal_path=journal, pad_material=pad_material)
    print("  FAIL: tampered journal was accepted")
    sys.exit(1)
except CorruptJournalException as e:
    print(f"  correctly rejected tampered/rolled-back offset: {e}")

print("\n=== TEST C: tampered offset (rolled FORWARD, e.g. to skip/waste bytes) is also REJECTED ===")
with open(journal, "w") as f:
    json.dump({"consumed_offset": 50, "mac": data["mac"]}, f)  # offset changed, MAC not recomputed
try:
    OTPPadStore(pad_size=64, journal_path=journal, pad_material=pad_material)
    print("  FAIL: forward-tampered journal was accepted")
    sys.exit(1)
except CorruptJournalException as e:
    print(f"  correctly rejected forward-tampered offset: {e}")

print("\n=== TEST D: malformed JSON fails shut ===")
with open(journal, "w") as f:
    f.write("{ this is not valid json !!! ")
try:
    OTPPadStore(pad_size=64, journal_path=journal, pad_material=pad_material)
    print("  FAIL: malformed JSON was accepted")
    sys.exit(1)
except CorruptJournalException as e:
    print(f"  correctly rejected malformed JSON: {e}")

print("\n=== TEST E: missing required field fails shut ===")
with open(journal, "w") as f:
    json.dump({"consumed_offset": 10}, f)  # no 'mac' field
try:
    OTPPadStore(pad_size=64, journal_path=journal, pad_material=pad_material)
    print("  FAIL: journal missing MAC field was accepted")
    sys.exit(1)
except CorruptJournalException as e:
    print(f"  correctly rejected missing field: {e}")

print("\n=== TEST F: out-of-bounds offset fails shut ===")
with open(journal, "w") as f:
    json.dump({"consumed_offset": 9999, "mac": "deadbeef"}, f)
try:
    OTPPadStore(pad_size=64, journal_path=journal, pad_material=pad_material)
    print("  FAIL: out-of-bounds offset was accepted")
    sys.exit(1)
except CorruptJournalException as e:
    print(f"  correctly rejected out-of-bounds offset: {e}")

print("\n=== TEST G: failed construction leaves no locked-but-abandoned buffer ===")
# If __init__ raises, .clear() should have already run internally.
# We verify indirectly: repeated failed constructions must not exhaust the
# mlock limit or raise unrelated errors -- run several in a row.
with open(journal, "w") as f:
    f.write("still not json")
for i in range(5):
    try:
        OTPPadStore(pad_size=64, journal_path=journal, pad_material=pad_material)
    except CorruptJournalException:
        pass
print("  5 repeated failed constructions did not leak locked memory or raise unrelated errors -- PASS")

print("\n=== TEST H: legitimate journal (untampered) still loads correctly after all this abuse ===")
reset()
with OTPPadStore(pad_size=64, journal_path=journal, pad_material=pad_material) as store:
    off, ct = store.encrypt(b"STILL WORKS")
    pt = OTPPadStore.decrypt(ct, pad_material[off:off+len(ct)])
    assert pt == b"STILL WORKS"
print("  legitimate round-trip still works after hardening -- PASS")

reset()
print("\nALL JOURNAL HARDENING TESTS PASSED")
