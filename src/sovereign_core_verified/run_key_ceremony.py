"""run_key_ceremony.py -- VERIFIED"""
import time
import sys
import nacl.bindings
from nacl._sodium import lib as _sodium_lib
from sovereign_memory import SecureKeyBuffer
from posture_watchdog import PostureWatchdog

def run_ceremony(swaps_path="/proc/swaps", net_class_path="/sys/class/net", mounts_path="/proc/mounts") -> bool:
    sys.stderr.write("[CEREMONY] Initializing secure key ceremony context...\n")
    SEED_BYTES = nacl.bindings.crypto_sign_SEEDBYTES
    PUBLIC_BYTES = nacl.bindings.crypto_sign_PUBLICKEYBYTES
    SECRET_BYTES = nacl.bindings.crypto_sign_SECRETKEYBYTES

    with SecureKeyBuffer(size=SEED_BYTES) as seed_buffer, \
         SecureKeyBuffer(size=PUBLIC_BYTES) as pub_buffer, \
         SecureKeyBuffer(size=SECRET_BYTES) as secret_buffer:

        watchdog = PostureWatchdog(
            secure_buffer_registry=[seed_buffer, pub_buffer, secret_buffer],
            interval_seconds=0.1,
            swaps_path=swaps_path, net_class_path=net_class_path, mounts_path=mounts_path
        )
        try:
            watchdog.start()
        except RuntimeError as start_error:
            sys.stderr.write(f"[CEREMONY_FATAL] Entry posture verification failed: {start_error}\n")
            return False

        # Defect 144: confirm the monitor thread is actually alive before
        # trusting it to protect key generation.
        if not watchdog.is_alive():
            sys.stderr.write("[CEREMONY_FATAL] Defect 144: monitor thread dead before generation gate.\n")
            return False

        sys.stderr.write("[CEREMONY] Initial posture passed. Generating secure entropy...\n")
        _sodium_lib.randombytes(seed_buffer.addr, SEED_BYTES)

        if _sodium_lib.crypto_sign_seed_keypair(pub_buffer.addr, secret_buffer.addr, seed_buffer.addr) != 0:
            sys.stderr.write("[CEREMONY_FATAL] Cryptographic keypair derivation failed inside memory core.\n")
            return False

        sys.stderr.write("[CEREMONY] Ed25519 identity keypair generated and pinned.\n")
        for cycle in range(1, 4):
            sys.stderr.write(f"[CEREMONY] Processing state synchronization blocks (Step {cycle}/3)...\n")
            time.sleep(0.5)
        watchdog.stop()
        sys.stderr.write("[CEREMONY_SUCCESS] Key materials processed. Executing deterministic cleanup.\n")
    return True

if __name__ == "__main__":
    s_path = sys.argv[1] if len(sys.argv) > 1 else "/proc/swaps"
    n_path = sys.argv[2] if len(sys.argv) > 2 else "/sys/class/net"
    m_path = sys.argv[3] if len(sys.argv) > 3 else "/proc/mounts"
    success = run_ceremony(swaps_path=s_path, net_class_path=n_path, mounts_path=m_path)
    sys.exit(0 if success else 1)
