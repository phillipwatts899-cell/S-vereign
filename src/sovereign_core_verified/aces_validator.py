"""
aces_validator.py -- VERIFIED / AUTHORITATIVE
Air-Gapped Ceremony Environment Validator (A-CES).
"""
import os
import sys

IFF_UP = 0x1
PHYSICAL_DEVICE_PREFIXES = ("/dev/sd", "/dev/nvme", "/dev/mmcblk", "/dev/vd", "/dev/xvd", "/dev/hd")

def verify_swap_posture(swaps_path: str = "/proc/swaps") -> tuple[bool, str]:
    try:
        with open(swaps_path, "r") as f:
            lines = [line for line in f.read().splitlines() if line.strip()]
    except OSError as e:
        return False, f"Could not read {swaps_path}: {e}"
    if len(lines) <= 1:
        return True, "No active swap devices detected."
    return False, f"Active swap device(s) detected: {lines[1:]}"

def verify_network_posture(net_class_path: str = "/sys/class/net") -> tuple[bool, str]:
    if not os.path.isdir(net_class_path):
        return False, f"{net_class_path} missing."
    offending = []
    try:
        interfaces = os.listdir(net_class_path)
    except OSError as e:
        return False, f"Could not list {net_class_path}: {e}"
    for iface in interfaces:
        if iface == "lo":
            continue
        flags_path = os.path.join(net_class_path, iface, "flags")
        try:
            with open(flags_path, "r") as f:
                raw = f.read().strip()
            flags_value = int(raw, 16)
        except (OSError, ValueError) as e:
            offending.append(f"{iface} (unreadable: {e})")
            continue
        if flags_value & IFF_UP:
            offending.append(f"{iface} (flags={raw}, IFF_UP set)")
    if offending:
        return False, f"Non-loopback interface(s) administratively up: {offending}"
    return True, "All non-loopback interfaces administratively down."

def verify_storage_posture(mounts_path: str = "/proc/mounts") -> tuple[bool, str]:
    try:
        with open(mounts_path, "r") as f:
            lines = [line for line in f.read().splitlines() if line.strip()]
    except OSError as e:
        return False, f"Could not read {mounts_path}: {e}"
    offending = []
    for line in lines:
        fields = line.split()
        if len(fields) < 4:
            continue
        device, target, fstype, options = fields[0], fields[1], fields[2], fields[3]
        if not device.startswith(PHYSICAL_DEVICE_PREFIXES):
            continue
        if "ro" not in set(options.split(",")):
            offending.append(f"{device} -> {target} (options={options})")
    if offending:
        return False, f"Writable physical block device(s) detected: {offending}"
    return True, "All physical block devices mounted read-only."

def enforce_air_gapped_posture(swaps_path: str = "/proc/swaps",
                                net_class_path: str = "/sys/class/net",
                                mounts_path: str = "/proc/mounts") -> None:
    s_ok, s_det = verify_swap_posture(swaps_path)
    print(f"[ACES] Swap posture: {'PASS' if s_ok else 'FAIL'} -- {s_det}", file=sys.stderr)
    n_ok, n_det = verify_network_posture(net_class_path)
    print(f"[ACES] Network posture: {'PASS' if n_ok else 'FAIL'} -- {n_det}", file=sys.stderr)
    st_ok, st_det = verify_storage_posture(mounts_path)
    print(f"[ACES] Storage posture: {'PASS' if st_ok else 'FAIL'} -- {st_det}", file=sys.stderr)
    if not (s_ok and n_ok and st_ok):
        print("[ACES_FATAL] Host does not meet air-gapped isolation requirements. "
              "Refusing to proceed with key ceremony.", file=sys.stderr)
        sys.exit(1)
    print("[ACES] Environmental posture verified.", file=sys.stderr)

if __name__ == "__main__":
    enforce_air_gapped_posture()
