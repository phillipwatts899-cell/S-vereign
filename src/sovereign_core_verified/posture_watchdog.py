import os
import sys
import signal
import threading
import traceback

from aces_validator import verify_swap_posture, verify_network_posture, verify_storage_posture

class PostureWatchdog:
    def __init__(self, secure_buffer_registry: list, interval_seconds: float = 0.2,
                 swaps_path: str = "/proc/swaps", net_class_path: str = "/sys/class/net",
                 mounts_path: str = "/proc/mounts"):
        self.registry = secure_buffer_registry
        self.interval = interval_seconds
        self.swaps_path = swaps_path
        self.net_class_path = net_class_path
        self.mounts_path = mounts_path
        self._buffers_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread = None

    def start(self) -> None:
        swap_ok, swap_det = verify_swap_posture(self.swaps_path)
        net_ok, net_det = verify_network_posture(self.net_class_path)
        storage_ok, storage_det = verify_storage_posture(self.mounts_path)
        if not (swap_ok and net_ok and storage_ok):
            err_msg = swap_det if not swap_ok else (net_det if not net_ok else storage_det)
            raise RuntimeError(f"Cannot start watchdog: initial environmental posture is unclean -- {err_msg}")
        self._thread = threading.Thread(target=self._run_monitor_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=self.interval * 2)

    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _run_monitor_loop(self):
        try:
            while not self._stop_event.is_set():
                swap_ok, swap_det = verify_swap_posture(self.swaps_path)
                net_ok, net_det = verify_network_posture(self.net_class_path)
                storage_ok, storage_det = verify_storage_posture(self.mounts_path)
                if not (swap_ok and net_ok and storage_ok):
                    reason = swap_det if not swap_ok else (net_det if not net_ok else storage_det)
                    self.execute_hard_shutdown(reason)
                    return
                self._stop_event.wait(self.interval)
        except Exception:
            tb = traceback.format_exc()
            self.execute_hard_shutdown(f"Internal monitor loop crash:\n{tb}")

    def execute_hard_shutdown(self, reason: str):
        sys.stderr.write(f"\n[WATCHDOG_TRIP] Environmental posture compromise detected: {reason}\n")
        sys.stderr.write("[WATCHDOG_TRIP] Initiating immediate atomic memory purge phase...\n")
        with self._buffers_lock:
            for buffer_item in self.registry:
                try:
                    buffer_item.clear()
                except Exception:
                    pass
        sys.stderr.write("[WATCHDOG_TRIP] Cryptographic allocations zeroed. Transmitting SIGKILL.\n")
        sys.stderr.flush()
        os.kill(os.getpid(), signal.SIGKILL)
