import sys
from sovereign_memory import SecureKeyBuffer
from otp_transport import generate_box_keypair, seal_pad, open_sealed, SealFailedError, BOX_SEALBYTES

print("=== TEST 1: keypair generation, no segfault, correct sizes ===")
pk_a, sk_a = generate_box_keypair()
pk_b, sk_b = generate_box_keypair()
assert pk_a.size == 32 and sk_a.size == 32
pk_a_bytes = bytes(pk_a.expose_raw_view())
pk_b_bytes = bytes(pk_b.expose_raw_view())
assert pk_a_bytes != pk_b_bytes, "two independently generated keypairs produced identical public keys"
print(f"  pk_a[:8]={pk_a_bytes[:8].hex()} pk_b[:8]={pk_b_bytes[:8].hex()} -- distinct, correct sizes, PASS")

print("\n=== TEST 2: seal + open round-trip, pointer-to-pointer, no intermediate corruption ===")
plaintext = b"THIS IS SIMULATED PAD MATERIAL 0123456789ABCDEF" * 4  # 200 bytes
with SecureKeyBuffer(len(plaintext)) as pt_buf:
    pt_buf.write_at_offset(plaintext)
    ciphertext = seal_pad(pt_buf, len(plaintext), pk_b_bytes)
    assert len(ciphertext) == len(plaintext) + BOX_SEALBYTES
    assert ciphertext != plaintext, "ciphertext must not equal plaintext"

    with SecureKeyBuffer(len(plaintext)) as out_buf:
        pt_len = open_sealed(ciphertext, pk_b, sk_b, out_buf)
        recovered = bytes(out_buf.expose_raw_view())[:pt_len]
        assert recovered == plaintext, f"round-trip MISMATCH: {recovered!r} != {plaintext!r}"
print(f"  sealed {len(plaintext)} bytes -> {len(ciphertext)} byte ciphertext -> recovered exact plaintext -- PASS")

print("\n=== TEST 3: tampered ciphertext MUST fail closed, not return garbage ===")
tampered = bytearray(ciphertext)
tampered[10] ^= 0xFF  # flip a bit in the middle of the sealed box
with SecureKeyBuffer(len(plaintext)) as out_buf:
    try:
        open_sealed(bytes(tampered), pk_b, sk_b, out_buf)
        print("  FAIL: tampered ciphertext was accepted")
        sys.exit(1)
    except SealFailedError as e:
        print(f"  correctly rejected tampered ciphertext: {e}")

print("\n=== TEST 4: wrong recipient keypair MUST fail closed ===")
with SecureKeyBuffer(len(plaintext)) as out_buf:
    try:
        open_sealed(ciphertext, pk_a, sk_a, out_buf)  # A tries to open a box sealed for B
        print("  FAIL: wrong-keypair open was accepted")
        sys.exit(1)
    except SealFailedError as e:
        print(f"  correctly rejected wrong-keypair open attempt: {e}")

print("\n=== TEST 5: truncated ciphertext (below SEALBYTES) rejected before touching FFI ===")
with SecureKeyBuffer(64) as out_buf:
    try:
        open_sealed(b"too short", pk_b, sk_b, out_buf)
        print("  FAIL: truncated ciphertext was accepted")
        sys.exit(1)
    except ValueError as e:
        print(f"  correctly rejected truncated ciphertext pre-FFI: {e}")

print("\n=== TEST 6: oversized plaintext for target out_buf rejected before touching FFI ===")
big_plain = b"X" * 500
with SecureKeyBuffer(500) as pt_buf:
    pt_buf.write_at_offset(big_plain)
    ct = seal_pad(pt_buf, 500, pk_b_bytes)
    with SecureKeyBuffer(10) as tiny_out:  # deliberately too small
        try:
            open_sealed(ct, pk_b, sk_b, tiny_out)
            print("  FAIL: oversized plaintext into undersized buffer was accepted")
            sys.exit(1)
        except ValueError as e:
            print(f"  correctly rejected oversized-plaintext-into-undersized-buffer: {e}")

print("\n=== TEST 7: stress -- 20 sequential seal/open cycles, no segfault, no leak crash ===")
for i in range(20):
    msg = f"pad chunk number {i}".encode() * 3
    with SecureKeyBuffer(len(msg)) as pbuf:
        pbuf.write_at_offset(msg)
        ct = seal_pad(pbuf, len(msg), pk_b_bytes)
        with SecureKeyBuffer(len(msg)) as obuf:
            n = open_sealed(ct, pk_b, sk_b, obuf)
            assert bytes(obuf.expose_raw_view())[:n] == msg
print("  20 sequential cycles completed with no crash and correct results -- PASS")

pk_a.clear(); sk_a.clear(); pk_b.clear(); sk_b.clear()
print("\nALL TRANSPORT PHASE 1 TESTS PASSED")
