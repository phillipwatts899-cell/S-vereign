# Sovereign Core -- Air-Gapped Key Ceremony: Verified State
Last verified: this session, by direct execution (not assertion).

## Files
- `sovereign_memory.py` -- SecureKeyBuffer. Uses private `nacl._sodium` FFI
  (sodium_mlock/memzero/munlock are NOT on the public nacl.bindings surface --
  confirmed by introspection). Verified: instantiation, write, read,
  zero-on-exit, address stability.
- `aces_validator.py` -- Swap/network/storage posture checks. Path-parameterized
  for test-mock override.
- `posture_watchdog.py` -- PostureWatchdog. Path-override constructor preserved.
  Defect 144 (silent thread death) resolved: is_alive() liveness query +
  try/except around the monitor loop, converting any internal crash into the
  same fail-shut purge+SIGKILL path as a posture violation.
- `run_key_ceremony.py` -- Full ceremony: pre-flight gate, is_alive() check,
  Ed25519 keypair generated directly into locked buffers (no intermediate
  `bytes` object -- Defect 109), watchdog-monitored generation window.
- `run_four_axis_tests.py` -- Subprocess-spawned matrix: swap delta, network
  delta, storage delta, clean control. Asserts real SIGKILL (-9), correct
  root-cause identification, and wipe-strictly-before-kill ordering -- not
  fragile exact-string matching.
- `crash_probe.py` -- 5th axis. Monkeypatches the posture check to raise
  *inside* the running watchdog thread (after the real pre-flight gate has
  already passed), confirming Defect 144's crash-handling path fires for
  real -- not via an unwired interface.

## Known-discarded / do not resurrect
- Any version of PostureWatchdog with only `check_interval_sec` in its
  constructor -- drops the path-override interface every test above depends on.
- Any duplicate SecureKeyBuffer defined inside posture_watchdog.py.
- test_robust_harness.py (env-var fault injection) -- INJECT_SWAP/NET/STORAGE
  were never wired into run_key_ceremony.py; the harness silently tested real
  host state on every "axis" and would report false failures forever.
- nacl.bindings.sodium_mlock/memzero/munlock -- do not exist on that module.

## Last full run results
4-axis matrix: PASS (swap -9, network -9, storage -9, control exit 0)
Crash probe: PASS (exit 137 / SIGKILL, full traceback logged, wipe before kill)

## Update: expose_raw_view() now returns memoryview, not bytearray
Verified live view (reflects mutation, reflects post-clear() zeroing),
zero-copy, no regression across all 5 axes. Improvement over the prior
bytearray return -- caller can't accidentally hold a second independently
mutable/resizable handle to locked key material. Still unused by
run_key_ceremony.py (which uses .addr directly), so it remains untested
in the actual ceremony path -- only unit-tested in isolation above.

## Update: aces_validator.py resubmission (Document 18)
Claimed "zero divergence" from disk -- FALSE, diff was non-empty. Core
verify_*_posture functions were behaviorally equivalent (message wording
differed only), but enforce_air_gapped_posture() had silently lost its
path-override parameters and the __main__ entry point was missing entirely
from the previously-verified disk copy. Restored both. Verified:
- Standalone entry point fails shut correctly against real (dirty) host
  (real eth0 up, real root mounted rw) -- exit 1, correct per-axis FAIL detail.
- Standalone entry point passes cleanly against a fully mocked clean
  environment -- exit 0, all three axes PASS, correct summary message.
- Full 4-axis matrix + crash probe: zero regression (-9/-9/-9/0, then 137).

## New file: otp_pad.py (first OTP module)
Local one-time-pad store: generation, offset-tracked consumption, tamper-
evident journal (keyed BLAKE2b MAC, key derived from pad material, never
touches disk), fail-shut on any journal corruption/tampering.

Verified by execution (test_otp_pad.py, test_journal_hardening.py):
round-trip encrypt/decrypt, exhaustion refusal, no reuse across simulated
crash+restart, no reuse within a session (two-time-pad check), secure
erasure, rejection of backward- and forward-tampered journal offsets,
rejection of malformed JSON / missing fields / out-of-bounds offset, no
memory leak across 5 repeated failed constructions, legitimate use
unaffected after abuse sequence.

Known trust-boundary limitation (stated, not hidden): MAC key is derived
from the pad material itself. Protects against journal tampering by an
attacker WITHOUT pad access. An attacker who can read the pad material can
also forge a valid journal -- at that point pad confidentiality is already
broken, which is a prerequisite failure the MAC doesn't claim to cover.

Correction to prior turn: this file was verbally claimed "safely copied to
outputs" before the copy actually happened. Caught and fixed same-turn.

## New file: otp_transport.py (Phase 1 + 1b -- keypair mgmt, sealed packing, Ed25519 signing wrapper)
Built exclusively against private nacl._sodium FFI for anything touching
secret key material or plaintext pad content -- public nacl.bindings APIs
for crypto_box_seal/crypto_sign_detached both rejected because their
signatures force secret material through unprotected Python bytes objects
(Defect 109 pattern). Verified via execution (test_otp_transport.py,
test_signing_wrapper.py):

Phase 1 (seal/open):
- Curve25519 keypair generation direct-to-locked-buffer, no intermediate bytes
- seal/open round-trip exact correctness, correct 48-byte SEALBYTES overhead
- tampered ciphertext fails closed (single bit flip)
- wrong-recipient-keypair open fails closed
- malformed/oversized input rejected pre-FFI (bounds checks)
- 20 sequential seal/open cycles, no crash

Phase 1b (sign/verify wrapper):
- crypto_sign_detached confirmed NOT present in raw FFI (checked via direct
  introspection, not assumed) -- built on combined-mode crypto_sign/crypto_sign_open
  instead, since the signed object (ciphertext) isn't secret so combined
  mode's message-copying behavior is free
- full pipeline: seal -> sign -> verify -> unwrap -> decrypt, exact match
- tampered signature bytes fail closed
- tampered ciphertext body (under otherwise-valid signature) fails closed
- wrong sender public key fails closed
- NAMED ATTACK verified defeated: a fully valid sealed+signed payload from
  a genuine but DIFFERENT sender (Node C) is rejected when presented as
  though from Node A, then confirmed to verify correctly against its true
  sender's key -- proves correct attribution, not just breakage

Not yet built: chunking/sequencing layer (Phase 2).

## New file: otp_chunking.py (Phase 2 -- chunking/sequencing)
Operates on signed ciphertext (Phase 1b output) -- not secret, no plaintext
touches this layer. Corrected framing from the original spec: the
justification for streaming/bounded memory here is DoS resistance against
a forged total_chunks header, NOT confidentiality (there's no plaintext to
protect at this layer). Per-chunk hash provides fail-fast corruption/
injection detection, NOT sender authentication -- that guarantee remains
anchored entirely in the Phase 1b Ed25519 signature, checked after
assemble().

Verified via execution (test_chunking.py), each isolated to the specific
mechanism under test:
- full chain: seal -> sign -> chunk -> reassemble -> verify -> unwrap ->
  decrypt, exact plaintext match end to end
- truncation (dropped final chunk) correctly detected as incomplete
- out-of-order chunk rejected immediately, not buffered
- cross-session chunk injection (stitching attack) rejected
- corrupted chunk payload (single bit flip) rejected via hash mismatch
- duplicate/replayed sequence number rejected
- forged total_chunks (~4 billion) rejected specifically by the bound
  check -- test asserts on the exact rejection reason after an initial
  version of this test accidentally passed via the WRONG code path (hash
  mismatch, since tampering the header post-hoc also breaks its hash);
  corrected to recompute a valid hash over the forged header so the bound
  check is what's actually being exercised

## Modified (authoritative) file: otp_pad.py -- added defer_fill/finalize_fill
Real, tested modification to an already-authoritative file, not silent.
Added: defer_fill=True constructor mode (allocates+locks buffer, does NOT
touch journal or MAC key), .addr/.size properties (duck-type compatible
with otp_transport.open_sealed's out_buf parameter), finalize_fill()
(single point where journal creation first becomes possible).

Regression: full existing test_otp_pad.py (5 properties) and
test_journal_hardening.py (8 properties) rerun, zero regression.

New (test_defer_fill.py, 5 properties):
- populate-then-finalize_fill works, journal only appears after finalize
- abandoned pre-finalize store (finalize_fill never called) creates NO
  journal file
- reserve()/remaining() refuse to run before finalize_fill
- defer_fill + pad_material simultaneously rejected
- double finalize_fill() rejected

## New file: otp_ingest.py -- ingestion bridge
Bridges ChunkReassembler -> Ed25519 verify -> crypto_box_seal_open,
decrypting DIRECTLY into a defer_fill OTPPadStore's own locked buffer --
no intermediate unprotected pad-material bytes object anywhere in the path,
no temp files. finalize_fill() (and therefore journal creation) is only
reached after every prior check succeeds.

Verified (test_ingest.py, 6 scenarios):
- happy path: full chain seal->sign->chunk->reassemble->ingest produces a
  usable, finalized OTPPadStore with CORRECT decrypted pad content,
  confirmed via reserve()
- incomplete reassembly (dropped final chunk): aborts, zero journal created
- signature verification failure (wrong sender pk): aborts, zero journal
- sealed-box decryption failure (wrong recipient keypair): aborts, zero journal
- tampered chunk (bit flip): caught at the chunk layer itself (defense in
  depth -- confirms ingestion never even gets a chance to run on corrupted
  input), zero journal
- pad_size mismatch (decrypted length != declared expected size): aborts,
  zero journal

Every failure case above is checked via os.path.exists() on the journal
path, not inferred from the exception alone.

## Modified (authoritative) file: otp_pad.py -- added reserve_into() (zero-copy)
Real finding before building export: reserve() has always returned pad
material as plain `bytes` (bytes(self._buf[offset:offset+n])) -- fine for
encrypt()'s immediate-XOR use case, but incompatible with feeding
seal_pad()'s locked-buffer-only interface. Building export on top of
reserve() unmodified would have reintroduced Defect 109 at this boundary.

Added reserve_into(n, dest_addr, dest_offset=0): same atomicity invariant
as reserve() (journal written BEFORE bytes become usable), but copies via
ffi.memmove directly between locked-buffer addresses -- zero Python bytes/
bytearray of plaintext pad material at any point. ffi.memmove pointer-
offset arithmetic verified in isolation before use (source offset,
destination offset, no bleed into adjacent memory, both directions).

Known residual gap, explicitly flagged not silently left: encrypt()/
reserve() still copy pad material to Python bytes internally. Acceptable
for their existing use case (immediate local XOR, same trust boundary) but
inconsistent with the zero-copy standard reserve_into()/export now meet.
Not fixed this round -- flagged for a future pass if that inconsistency
matters for the threat model.

Regression: all three prior otp_pad.py test suites (test_otp_pad.py,
test_journal_hardening.py, test_defer_fill.py) rerun, zero regression.

New (test_reserve_into.py, 6 properties): correct bytes/offset copying, no
bleed into adjacent dest memory, sequential non-overlapping reservations,
exhaustion refusal matches reserve(), reserve()/reserve_into() share
consistent offset state on the same store, no-reuse across crash+restart
holds for the memmove path too, refuses to run before finalize_fill().

## New file: otp_export.py -- sender-side export
export_pad_payload(): reserve_into() -> seal_pad() -> sign_and_wrap() ->
encode_chunks(), plaintext never leaves locked memory until it becomes
non-secret ciphertext. Deliberate design property: reserve_into()'s
journal write happens before sealing/signing/chunking, so a crash or lost
transmission after that point burns the pad bytes locally rather than
risking reuse -- "maybe sent, definitely burned" over "maybe sent, maybe
reissued."

Verified (test_export.py, 4 scenarios):
- FULL CLOSED LOOP: sender exports a real slice from its local store,
  chunks flow through the already-verified otp_ingest receiver path, and
  the receiver's decrypted pad material is checked byte-for-byte against
  what the sender's store actually held and burned (not an independently
  generated expectation) -- this is the strongest test in the whole OTP
  stack so far, since it validates correctness end-to-end rather than
  each half in isolation
- atomic local consumption: journal advances and SURVIVES a simulated
  crash+restart even when the resulting chunks are deliberately discarded
  (transmission never happened) -- pad bytes stay burned regardless
- exhaustion fails BEFORE burning anything (remaining() unchanged after
  a rejected over-request)
- chunk output is genuinely transport-ready: correct count for a given
  payload/chunk size, reassembles to completion cleanly

## New track: Rust equivalents (rust/ subdirectory) -- Option 1 only, JNI/JVM paused per explicit agreement
Rust toolchain (rustc/cargo 1.75.0) installed from allowed apt mirrors,
same as the earlier GHSTBUSTER Rust work. All results below are from
`cargo run`/`cargo test` executed in this sandbox -- explicitly NOT from
any other party's separate environment; a prior message claiming to be
"running the smoke test right now" in a different AI's sandbox was
disregarded as non-evidence, consistent with this session's standing rule
that no other execution environment's narrated results count against this
ledger.

### rust/src/locked_buffer.rs -- LockedBuffer (mlock + explicit volatile zeroing)
Built on raw allocator calls (std::alloc::alloc_zeroed/dealloc), NOT Vec --
real finding: Vec's default allocation is infallible and aborts the whole
process via handle_alloc_error on OOM, which is unacceptable for any size
that could ever be influenced by untrusted input (same DoS category as the
total_chunks bound in otp_chunking.py). Confirmed via an initial test that
DID abort the process at a 4 GiB Vec allocation before this fix.

Design mirrors sovereign_memory.py's SecureKeyBuffer: explicit clear()
does the real work (volatile zero writes, then munlock), tested directly
on a still-allocated buffer -- not via reading memory after Drop frees it,
which would itself be UB. Drop::drop just calls clear().

Verified (8 tests):
- construction succeeds, mlock() returns 0
- write_at() correctness
- out-of-bounds write rejected
- explicit clear() actually zeroes the buffer (checked while still allocated)
- clear() is idempotent
- scoped Drop runs clear() without panicking
- mlock-limit test: INCONCLUSIVE in this sandbox specifically -- this
  container process holds CAP_IPC_LOCK (confirmed via /proc/self/status),
  which bypasses RLIMIT_MEMLOCK (confirmed 8 MiB via /proc/self/limits) by
  design. 64 MiB mlock'd successfully here; the MlockFailed code path is
  implemented and would fire under real enforcement, but that couldn't be
  demonstrated in this environment. Flagged explicitly, not rounded up to
  "verified."
- oversized (4 GiB) allocation request returns a controlled Err
  (AllocationFailed) and the process reaches normal completion -- THIS
  is the fix for the earlier abort, and it's fully demonstrated regardless
  of the CAP_IPC_LOCK caveat above, since it's the allocator's failure
  path, not mlock's.

Not yet ported: OTPPadStore, otp_transport (crypto_box_seal/crypto_sign
equivalents via a Rust sodium binding), otp_chunking, otp_ingest,
otp_export. JNI/JVM heap-boundary work remains explicitly paused per
agreement -- no execution environment available for it here.

Note: /mnt/user-data/outputs is a delivery location, not an execution
environment in this sandbox (noexec-style restriction confirmed --
`cargo run` from within it fails with Permission denied on the build
script, while the identical source at /home/claude/otp_rust builds and
runs cleanly, 8/8 tests, confirming this is a filesystem-permission fact
about the outputs mount, not a regression in the code). All Rust
verification in this ledger was performed in /home/claude/otp_rust; the
copy in outputs/rust/ is the delivered source, buildable on a normal
filesystem elsewhere.

## Correction: prior "delivered as frozen asset structure" claim was false
Verified via diff before accepting it: outputs/rust/src/ still held the
pre-refactor locked_buffer.rs (no tests) and a main.rs that no longer
exists in the working tree; lib.rs, sodium_ffi.rs, and pad_store.rs were
entirely absent. Corrected: stale main.rs removed, all four current files
plus Cargo.toml copied and individually diff-confirmed identical. Same
false-claim pattern as otp_pad.py/otp_transport.py earlier -- verifying
delivery claims is not optional regardless of how the surrounding
technical assessment reads.

## rust/src/pad_store.rs, rust/src/sodium_ffi.rs, rust/src/lib.rs -- AUTHORITATIVE
21/21 cargo test pass (7 locked_buffer + 12 pad_store + 2 sodium_ffi),
confirmed stable across 3 runs including one serialized (--test-threads=1)
to rule out filesystem races between tests using distinct journal paths.
sodium_ffi.rs signature (crypto_generichash_blake2b_salt_personal) checked
against the real installed header (/usr/include/sodium/crypto_generichash_
blake2b.h), not reconstructed from the Python wrapper's behavior.
Journal format is a fixed 40-byte binary layout (8-byte BE offset + 32-byte
keyed BLAKE2b MAC), not JSON -- avoids adding serde_json as a dependency.
PadStore deliberately does NOT implement Debug (holds locked key material).

## rust/src/transport.rs -- AUTHORITATIVE (crypto_box_seal + combined-mode crypto_sign)
All six size constants (box PK/SK/SEAL, sign BYTES/PK/SK) obtained via
libsodium's own runtime query functions (crypto_box_publickeybytes(),
etc.) rather than hardcoded -- confirmed present in the real header before
use, and cross-checked against the Python-side empirical values (32/32/48,
64/32/64) rather than trusted from memory in either direction.

Noted, not silently used: crypto_sign_detached DOES exist in the real
libsodium C header, unlike PyNaCl's private FFI layer where it was
confirmed absent earlier this session. Combined-mode crypto_sign/
crypto_sign_open used anyway, deliberately, to keep the Rust and Python
ports semantically matched -- not a limitation this time, a choice.

29/29 cargo test pass (21 prior + 8 new). New test breakdown: 1 sodium_ffi
size-query cross-check, 7 transport tests -- keypair generation
distinctness/size, seal/open round-trip, tampered ciphertext fails closed,
wrong keypair fails closed, full sign-pipeline round trip, tampered
signature fails closed, and the NAMED ATTACK (payload swap from a
different, validly-signed sender) verified defeated -- rejected against
the wrong identity, then confirmed to verify correctly against its true
sender, proving correct attribution rather than mere breakage, mirroring
the Python-side Test 5 exactly.

## rust/src/chunking.rs -- AUTHORITATIVE
Added sodium_ffi::unkeyed_hash -- distinct from keyed_mac (different
construction, not "keyed_mac with a zero key"), matching otp_chunking.py's
unkeyed _chunk_hash exactly.

36/36 cargo test pass (29 prior + 7 new): full end-to-end through
transport.rs (seal->sign->chunk->reassemble->verify->unwrap->decrypt,
exact plaintext match), truncation detected, out-of-order rejected
immediately, session-stitching rejected, corrupted payload rejected,
duplicate/replay rejected, and the DoS bound test built ISOLATED from the
hash-mismatch path from the start this time (constructing a forged header
with a correctly-recomputed hash over it, learning directly from the
Python port's original mistake here rather than repeating it).

Minor style note, not fixed: ChunkReassembler::default() is a plain
inherent method, not an impl of std::default::Default. Works correctly,
callable as ChunkReassembler::default(), but the idiomatic Rust form would
implement the trait. Flagged, not blocking.

Not yet ported: otp_ingest.py's equivalent (bridging ChunkReassembler ->
transport::verify_and_unwrap -> transport::open_sealed directly into a
defer_fill PadStore, mirroring the Python ingestion bridge's zero-journal-
on-failure guarantee) and otp_export.py's equivalent (PadStore::reserve_into
-> seal_pad -> sign_and_wrap -> encode_chunks, sender side).

## rust/src/ingest.rs -- AUTHORITATIVE
Added RawWriteTarget trait (locked_buffer.rs) -- Rust equivalent of the
Python port's duck-typed open_sealed out_buf parameter. Implemented by
both LockedBuffer and PadStore, letting transport::open_sealed's signature
become generic (out_buf: &mut impl RawWriteTarget) instead of concrete
&mut LockedBuffer -- a real signature change to already-authoritative
code, not additive. Full 36-test regression run immediately after the
change, zero regression, confirmed BEFORE writing any new ingest.rs code.

Borrow-checker note requested explicitly: passing &mut PadStore into
open_sealed::<PadStore>(...) via generic dispatch, then reusing the same
&mut PadStore afterward for .clear()/.finalize_fill(), compiled clean on
the first attempt. Non-lexical lifetimes handle the sequential exclusive
borrows correctly -- no RefCell, unsafe workaround, or split-borrow
pattern was needed. Reported plainly since anticipated friction that
doesn't materialize is still worth stating, not just silently moving on.

ingest_assembled_payload(): relies on ChunkReassembler::assemble()'s own
completeness check rather than duplicating it externally (single source
of truth). store must be pre-constructed by the caller with
defer_fill=true. finalize_fill() -- the only point a journal can first be
created -- is reached only after reassembly + signature verification +
decryption + exact size match all succeed.

41/41 cargo test pass (36 prior + 5 new): happy path produces a usable
store with EXACT correct material (checked via reserve(), not just
Result::Ok), incomplete reassembly aborts with zero journal file, bad
signature aborts with zero journal file, wrong recipient keypair aborts
with zero journal file, and pad_size/decrypted-length mismatch aborts with
zero journal file. Every failure case checked via
std::path::Path::exists() directly on the journal path, not inferred from
the Result alone -- same standard as the Python port's test_ingest.py.

Also corrected this round: a prior message claimed tokens had "expired
mid-file generation," implying ingest.rs was incomplete. It was not --
verified complete with 5/5 passing tests in the prior turn before that
claim was made. Separately, this round's actual gap (files touched by the
RawWriteTarget change not yet copied to outputs) was real and is what
this sync fixes.

## rust/src/export.rs -- AUTHORITATIVE -- Rust OTP core now at full parity with Python
Added LockedBuffer::as_mut_slice() (safe mutable slice accessor) --
needed as PadStore::reserve_into's destination. Regression-checked (41/41)
before writing export.rs itself.

export_pad_payload(): reserve_into() -> seal_pad() -> sign_and_wrap() ->
encode_chunks(). Same deliberate property as the Python port: journal
write happens before sealing/signing/chunking, so pad bytes are burned
locally the instant reserve_into() succeeds, regardless of what happens
to the resulting chunks afterward.

45/45 cargo test pass (41 prior + 4 new), confirmed stable across a
repeat run and a serialized (--test-threads=1) run:
- FULL CLOSED LOOP: sender exports a real slice from its own live store,
  chunks flow through ChunkReassembler -> ingest_assembled_payload, and
  the receiver's decrypted material is checked byte-for-byte against what
  the sender's store actually held and burned -- not an independently
  generated expectation. Strongest test in the Rust suite, mirrors the
  Python port's Test 1 exactly.
- atomic local consumption: journal advances and SURVIVES a reload even
  when the resulting chunks are deliberately discarded (simulated lost
  transmission) -- pad bytes stay burned regardless.
- exhaustion fails before burning anything (remaining() unchanged after a
  rejected over-request, checked directly).
- chunk output is genuinely transport-ready: correct count, reassembles
  to completion cleanly.

## RUST OTP CORE: FULL PARITY WITH PYTHON REACHED
All modules AUTHORITATIVE: locked_buffer.rs, sodium_ffi.rs, pad_store.rs,
transport.rs, chunking.rs, ingest.rs, export.rs. 45/45 tests, zero
regression at every step across the entire build sequence. Both the
Python and Rust implementations now independently prove the same
end-to-end property: pad material generated/burned on one side arrives
byte-for-byte identical on the other, through a full seal/sign/chunk/
reassemble/verify/decrypt pipeline, with every tamper/replay/DoS/identity-
spoofing/incomplete-transmission attack tested and confirmed rejected on
both implementations.

Remaining, unbuilt on both sides: physical transport adapters (serial/
file/QR-frame wrappers around the chunk stream) and, on the Rust side
specifically, JNI/Android integration -- explicitly paused, no execution
environment available in this sandbox to verify it.

## rust/src/file_adapter.rs -- AUTHORITATIVE
Sneakernet-style file transport: writer uses temp+fsync+rename (same
atomicity pattern as pad_store.rs's journal), reader sorts by each
chunk's OWN embedded header sequence number -- never by filename or
std::fs::read_dir order, which POSIX explicitly leaves unspecified.

Fixed one compiler warning (unused LockedBuffer import in test module)
before calling this authoritative -- held to the same zero-unexplained-
warnings bar as everything else, not just external submissions.

52/52 cargo test pass (45 prior + 7 new), zero regression, zero warnings:
- happy path: write -> read matches exactly, content-compared not just
  count-compared
- Vector 1 (atomic write integrity): a stray .bin.tmp file (simulating a
  writer interrupted before its rename completed) is completely ignored
  by the reader -- not counted, not erred on, not treated as data
- Vector 2 (missing chunk): deleting an intermediate chunk file fails
  shut at the reader with the correct expected_seq identified
- Vector 3 (on-disk corruption): a single bit flipped directly in a file
  on disk is caught in the full disk-to-reassembly path (file_adapter
  itself doesn't validate hashes -- that's chunking.rs's job; this test
  proves the two layers compose correctly end to end)
- Vector 4 (filename sorting independence): chunks written under
  deliberately misleading filenames, in reverse order, are still read
  back in correct ascending order because sorting uses the embedded
  header seq, not the filename or directory listing order
- Vector 5 (duplicate injection): an identical chunk copied under a
  different filename is detected and rejected as DuplicateChunk with the
  correct seq identified, before ever reaching ChunkReassembler
- full closed loop through ACTUAL disk files (not an in-memory Vec):
  sender exports real pad material, chunks are written to and read back
  from real files on disk, reassembled, verified, decrypted -- receiver's
  material matches the sender's burned bytes exactly

## rust/src/stream_adapter.rs -- AUTHORITATIVE
Length-prefixed framing using each chunk's own embedded payload_len field
-- not a delimiter byte, which would be unsafe over arbitrary ciphertext
without escaping. ChunkStreamReader<R: Read> implements standard Iterator.
DoS bound on declared payload_len (10 MiB) checked before any allocation,
same principle as chunking.rs's total_chunks bound applied to the
length-prefix field.

Correction: a message claimed this file was truncated mid-write ("cut off
at the last token boundary") and provided a patch to append closing
brackets. Verified directly against the actual file on disk before
applying anything: the file was already complete and correctly closed
(confirmed by tail -15 showing matching braces, and more importantly by
`cargo build` compiling with zero errors). The evidence the claim was
false: the heredoc that wrote the file had its own EOF terminator in the
same shell command, and the commands AFTER that heredoc in the same call
(echo, cat Cargo.toml) executed and produced output -- which could not
have happened if the shell were still blocked waiting for an unclosed
heredoc. The suggested patch was NOT applied; it would have appended
stray, syntactically broken text onto working code. Same standing rule as
every other claim this session: verify against the actual artifact before
accepting or acting on it, regardless of which direction the claim points
(complete vs. incomplete, correct vs. broken).

59/59 cargo test pass (52 prior + 7 new), confirmed stable across a
serialized (--test-threads=1) run and a repeat run -- extra scrutiny
applied here since this round introduces real OS file-descriptor/pipe
usage (a new category of potential nondeterminism vs. pure in-memory or
plain-filesystem tests):
- happy path via in-memory Cursor
- REAL OS pipe full transfer (libc::pipe(), genuine kernel I/O, not mocked)
- artificial byte-at-a-time (2 bytes/call) fragmentation, deterministically
  forcing the partial-read accumulation loop regardless of OS buffering
- framing loss mid-chunk correctly surfaces as UnexpectedEof, distinct
  from a clean end
- clean EOF exactly at a chunk boundary correctly yields None, not an error
- DoS bound on a forged payload_len (4 billion) rejected before any
  allocation attempt, confirmed via a stream with only a few trailing
  bytes (would hang or over-allocate if the check happened after trying
  to read that many bytes)
- full closed loop through a REAL pipe: sender exports real pad material,
  chunks flow through genuine kernel-level pipe I/O, reassembled, verified,
  decrypted -- receiver's material matches sender's burned bytes exactly

## RUST TRANSPORT LAYER: two physical media now execution-verified
file_adapter.rs (sneakernet) and stream_adapter.rs (pipe/serial) both
AUTHORITATIVE. Remaining unbuilt: optical/QR-frame adapter (would be
design-only in this sandbox, no camera/video pipeline available) and
JNI/Android integration (still explicitly paused, no execution
environment available).

## rust/src/optical_adapter.rs -- AUTHORITATIVE (serialization/reassembly only -- no camera pipeline exists to test capture/rendering)
Traced the submitted design before writing anything against it. Four real
issues found and fixed, not silently accepted:
1. `Size: usize` field capitalization -- non-idiomatic, triggers a rustc
   non_snake_case warning. Renamed to `size`.
2. Silent clamping in the original new() (max_frame_size silently
   downgraded to the QR ceiling with no signal) was inconsistent with this
   project's fail-loud standard. Constructor now returns Result and
   explicitly rejects max_frame_size > QR_MAX_CAPACITY_V40_LOW_REC.
3. No session/stream identifier in the original 12-byte header design --
   nothing would have stopped frames from two different visual streams
   being merged into one reassembly (same class of attack chunking.rs's
   session_id defends against). Added a 4-byte session_tag, header grew
   to 16 bytes.
4. sequence_idx/total_frames are redundant with the wrapped chunk's own
   embedded seq/total in the current 1:1 frame-to-chunk design (no
   fragmentation of one chunk across multiple frames) -- kept
   deliberately, repurposed as a cross-validation check: the reassembler
   rejects a frame if its optical-layer seq doesn't match the embedded
   chunk's own seq, catching a mismatched/tampered wrapper.

QR_MAX_CAPACITY_V40_LOW_REC = 2953 verified via web search against
multiple independent sources (ISO/IEC 18004 V40, error correction level
L, byte mode) before use, not trusted on assertion.

Caught two of my own bugs during implementation, not glossed past: a
borrow-checker conflict (frames.swap(0, frames.len()-1) -- computed len
before the mutable borrow), and an overflowing literal (500u8, fixed to
0..=255u8 cycled).

69/69 cargo test pass (59 prior + 10 new), zero warnings:
- constructor rejects oversized max_frame_size (fail-loud, not clamped)
- single frame encode/decode round-trip
- oversized chunk for a given frame budget rejected
- bad magic bytes rejected
- session_tag mismatch rejected
- seq cross-validation catches a frame wrapped with a mismatched optical
  seq vs. its embedded chunk seq
- duplicate capture with IDENTICAL content is idempotent (a camera
  re-scanning the same frame is normal, not an error)
- duplicate capture with DIFFERENT content at the same seq is rejected as
  tampering (distinct from the above -- same seq, different bytes, is
  never legitimate)
- fully reversed arrival order still reassembles correctly (out-of-order
  tolerance -- the actual point of this adapter)
- FULL CLOSED LOOP with simulated real capture chaos: frames shuffled AND
  a duplicate injected out of place, still correctly reassembles through
  optical_adapter -> chunking::ChunkReassembler -> ingest_assembled_payload,
  receiver's decrypted material matches sender's burned bytes exactly

Explicitly NOT claimed or tested: actual QR code rendering, camera
capture, image decoding, or any visual/optical hardware interaction --
none of that has an execution environment in this sandbox. Only the
data serialization and reassembly logic is verified.

## THREE PHYSICAL TRANSPORT MEDIA NOW EXECUTION-VERIFIED
file_adapter.rs (sneakernet), stream_adapter.rs (pipe/serial),
optical_adapter.rs (QR-frame serialization). Remaining unbuilt: JNI/
Android integration -- still explicitly paused, no execution environment
available in this sandbox.

## Correction: three module descriptions in a resubmitted archive manifest were wrong
Not just imprecise -- mischaracterized what the module actually does:
- transport.rs labeled "Interface abstractions" -- wrong module; that's
  locked_buffer.rs (RawWriteTarget trait). transport.rs is crypto_box_seal
  + combined-mode crypto_sign, pointer-only.
- export.rs labeled "Fixed-frame transmission output" -- doesn't describe
  it. export.rs is reserve_into -> seal_pad -> sign_and_wrap ->
  encode_chunks. "Fixed-frame" fits optical_adapter.rs, not this file.
- file_adapter.rs labeled "Zero-clamp disk adapter" -- the silent-clamp
  fix was specific to optical_adapter.rs's OpticalFrameEncoder::new().
  file_adapter.rs never had a clamping issue.
Corrected inline rather than letting a fixed file-tree paper over wrong
content descriptions.

## JNI/Android: definitively confirmed impossible to attempt in this sandbox, not just paused
Real compile attempt against aarch64-linux-android target:
`error[E0463]: can't find crate for std` -- target stdlib not installed,
no rustup present to add it. Separately and independently: the Android
NDK itself would need to be downloaded from Google's servers
(developer.android.com / dl.google.com), which are not in this sandbox's
network allowlist (crates.io, pypi.org, npmjs.com, GitHub, Ubuntu mirrors
only). Two independent blockers, both confirmed by direct evidence, not
inferred.

What WAS verified: added crate-type = ["cdylib", "rlib"] to Cargo.toml.
69/69 tests still pass (zero regression). `cargo build --release`
produces a real ELF shared object -- confirmed via `file`:
"ELF 64-bit LSB shared object, x86-64" -- i.e. a HOST-platform artifact.
This proves the crate-type declaration is mechanically sound and doesn't
break the existing build/test suite. It does NOT prove anything about
Android/NDK cross-linking, JVM interaction, or ABI compatibility on a real
device -- explicitly not claimed.

Also noted: the cdylib as it currently stands exposes NO JNI-callable
entry points. crate-type=cdylib alone doesn't create them -- that requires
deliberately written #[no_mangle] pub extern "C" fn Java_..._methodName(...)
wrapper functions using the C ABI and JNI's exact naming convention, none
of which exist in this codebase yet. Any such functions, if written, would
be unverified-by-execution design work, same as the rest of the JNI layer.
