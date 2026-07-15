import sys
from sovereign_memory import SecureKeyBuffer
from otp_transport import (
    generate_box_keypair, seal_pad, open_sealed, SealFailedError,
    generate_sign_keypair, sign_and_wrap, verify_and_unwrap, SignatureVerificationError,
    SIGN_BYTES,
)

print("=== TEST 1: full pipeline -- seal, sign, verify, unwrap, decrypt ===")
box_pk_a, box_sk_a = generate_box_keypair()
box_pk_b, box_sk_b = generate_box_keypair()
sign_pk_a, sign_sk_a = generate_sign_keypair()
sign_pk_a_bytes = bytes(sign_pk_a.expose_raw_view())
box_pk_b_bytes = bytes(box_pk_b.expose_raw_view())

plaintext = b"REAL PAD MATERIAL SEGMENT: " + bytes(range(50))
with SecureKeyBuffer(len(plaintext)) as pt_buf:
    pt_buf.write_at_offset(plaintext)
    ciphertext = seal_pad(pt_buf, len(plaintext), box_pk_b_bytes)

signed_ct = sign_and_wrap(ciphertext, sign_sk_a)
print(f"  ciphertext={len(ciphertext)}B, signed_ciphertext={len(signed_ct)}B (overhead={len(signed_ct)-len(ciphertext)}, expected {SIGN_BYTES})")
assert len(signed_ct) - len(ciphertext) == SIGN_BYTES

# receiver side: verify signature first, THEN decrypt
recovered_ct = verify_and_unwrap(signed_ct, sign_pk_a_bytes)
assert recovered_ct == ciphertext, "unwrapped ciphertext doesn't match original"
with SecureKeyBuffer(len(plaintext)) as out_buf:
    n = open_sealed(recovered_ct, box_pk_b, box_sk_b, out_buf)
    recovered_pt = bytes(out_buf.expose_raw_view())[:n]
    assert recovered_pt == plaintext
print("  full pipeline round-trip: seal -> sign -> verify -> unwrap -> decrypt -- exact match, PASS")

print("\n=== TEST 2: tampered SIGNATURE bytes fail closed ===")
tampered_sig = bytearray(signed_ct)
tampered_sig[5] ^= 0xFF  # flip a bit inside the signature portion (first SIGN_BYTES)
try:
    verify_and_unwrap(bytes(tampered_sig), sign_pk_a_bytes)
    print("  FAIL: tampered signature was accepted")
    sys.exit(1)
except SignatureVerificationError as e:
    print(f"  correctly rejected tampered signature: {e}")

print("\n=== TEST 3: tampered CIPHERTEXT portion (signature intact) fails closed ===")
tampered_body = bytearray(signed_ct)
tampered_body[-5] ^= 0xFF  # flip a bit near the end, inside the ciphertext portion
try:
    verify_and_unwrap(bytes(tampered_body), sign_pk_a_bytes)
    print("  FAIL: tampered ciphertext body (under a now-invalid signature) was accepted")
    sys.exit(1)
except SignatureVerificationError as e:
    print(f"  correctly rejected tampered ciphertext body: {e}")

print("\n=== TEST 4: wrong sender public key fails closed ===")
sign_pk_x, sign_sk_x = generate_sign_keypair()  # unrelated third identity
sign_pk_x_bytes = bytes(sign_pk_x.expose_raw_view())
try:
    verify_and_unwrap(signed_ct, sign_pk_x_bytes)  # verifying A's message against X's key
    print("  FAIL: verification against wrong public key was accepted")
    sys.exit(1)
except SignatureVerificationError as e:
    print(f"  correctly rejected wrong-sender-key verification: {e}")

print("\n=== TEST 5: THE NAMED ATTACK -- swap in a validly-sealed payload from a DIFFERENT sender ===")
# Node C generates its own valid signing identity and seals its own valid
# message for the SAME recipient B. This produces a fully legitimate,
# correctly-sealed, correctly-signed block -- just not from A.
sign_pk_c, sign_sk_c = generate_sign_keypair()
plaintext_c = b"MALICIOUS SUBSTITUTE PAYLOAD FROM NODE C"
with SecureKeyBuffer(len(plaintext_c)) as pt_buf_c:
    pt_buf_c.write_at_offset(plaintext_c)
    ciphertext_c = seal_pad(pt_buf_c, len(plaintext_c), box_pk_b_bytes)
signed_ct_c = sign_and_wrap(ciphertext_c, sign_sk_c)  # validly signed, by C, not A

# Attacker substitutes C's fully-valid signed block in place of A's, and
# tells the receiver "this is from A" (verifies against A's public key).
try:
    verify_and_unwrap(signed_ct_c, sign_pk_a_bytes)
    print("  FAIL: swapped payload from a different (even validly-signed) sender was accepted as A's")
    sys.exit(1)
except SignatureVerificationError as e:
    print(f"  correctly rejected swapped payload impersonating a different sender: {e}")
# and confirm it DOES verify correctly against its true, honest sender C
recovered_c = verify_and_unwrap(signed_ct_c, bytes(sign_pk_c.expose_raw_view()))
assert recovered_c == ciphertext_c
print("  ...and correctly VERIFIES when checked against its true sender C's key -- attack defeated, not just broken")

for buf in [box_pk_a, box_sk_a, box_pk_b, box_sk_b, sign_pk_a, sign_sk_a, sign_pk_x, sign_sk_x, sign_pk_c, sign_sk_c]:
    buf.clear()

print("\nALL SIGNING WRAPPER TESTS PASSED")
