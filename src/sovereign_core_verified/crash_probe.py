"""
Standalone crash-injection probe for Defect 144.
Monkeypatches aces_validator.verify_swap_posture to raise inside the
watchdog's own module namespace, forcing a genuine internal thread crash
(not a posture failure) and confirming the try/except -> emergency purge
-> SIGKILL path actually fires.
"""
import sys
import time
import nacl.bindings
from sovereign_memory import SecureKeyBuffer
import posture_watchdog

def _boom(*args, **kwargs):
    raise RuntimeError("SIMULATED_INTERNAL_CRASH: sensor read corrupted mid-check")

import os
os.makedirs("/tmp/crash_probe/net/lo", exist_ok=True)
os.makedirs("/tmp/crash_probe/net/eth0", exist_ok=True)
with open("/tmp/crash_probe/swaps", "w") as f: f.write("Filename Type Size Used Priority\n")
with open("/tmp/crash_probe/net/lo/flags", "w") as f: f.write("0x1003\n")
with open("/tmp/crash_probe/net/eth0/flags", "w") as f: f.write("0x1002\n")  # administratively down
with open("/tmp/crash_probe/mounts", "w") as f: f.write("/dev/vda / ext4 ro,relatime\n")

with SecureKeyBuffer(size=nacl.bindings.crypto_sign_SEEDBYTES) as seed_buffer:
    watchdog = posture_watchdog.PostureWatchdog(
        secure_buffer_registry=[seed_buffer],
        interval_seconds=0.1,
        swaps_path="/tmp/crash_probe/swaps",
        net_class_path="/tmp/crash_probe/net",
        mounts_path="/tmp/crash_probe/mounts"
    )
    # Let start()'s pre-flight gate run against the REAL function first --
    # only patch after the thread is confirmed alive, so we're testing the
    # loop's crash handling, not accidentally tripping the entry gate.
    watchdog.start()
    if not watchdog.is_alive():
        sys.stderr.write("[PROBE_ABORT] Thread never started -- cannot test loop crash handling.\n")
        sys.exit(3)
    sys.stderr.write("[PROBE] Watchdog started, thread alive. Injecting crash into next loop iteration...\n")
    posture_watchdog.verify_swap_posture = _boom
    time.sleep(2.0)
    # Should never reach here -- SIGKILL should have fired already
    sys.stderr.write("[PROBE_FAIL] Process survived 2s past simulated internal crash -- Defect 144 NOT resolved.\n")
    sys.exit(2)
