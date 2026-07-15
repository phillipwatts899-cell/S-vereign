import os, sys, time, subprocess, shutil

def run_isolated_axis(test_name, setup_fault_func):
    sandbox_dir = f"/tmp/sandbox_{test_name.lower()}"
    if os.path.exists(sandbox_dir):
        shutil.rmtree(sandbox_dir)
    os.makedirs(sandbox_dir)
    mock_swaps = os.path.join(sandbox_dir, "swaps")
    mock_net = os.path.join(sandbox_dir, "net")
    mock_mounts = os.path.join(sandbox_dir, "mounts")
    os.makedirs(os.path.join(mock_net, "lo"))
    os.makedirs(os.path.join(mock_net, "eth0"))
    with open(mock_swaps, "w") as f: f.write("Filename Type Size Used Priority\n")
    with open(os.path.join(mock_net, "lo", "flags"), "w") as f: f.write("0x1003\n")
    with open(os.path.join(mock_net, "eth0", "flags"), "w") as f: f.write("0x1002\n")
    with open(mock_mounts, "w") as f: f.write("/dev/vda / ext4 ro,relatime\n")

    proc = subprocess.Popen(
        [sys.executable, "run_key_ceremony.py", mock_swaps, mock_net, mock_mounts],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    time.sleep(0.4)
    setup_fault_func(mock_swaps, mock_net, mock_mounts)
    try:
        stdout, stderr = proc.communicate(timeout=3.0)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
    return proc.returncode, stdout, stderr

def fault_swap(s, n, m):
    with open(s, "a") as f: f.write("/dev/dm-0 partition 2097152 0 -2\n")
def fault_net(s, n, m):
    with open(os.path.join(n, "eth0", "flags"), "w") as f: f.write("0x1003\n")
def fault_storage(s, n, m):
    with open(m, "w") as f: f.write("/dev/vda / ext4 rw,relatime\n")
def fault_none(s, n, m):
    pass

if __name__ == "__main__":
    print("="*70)
    print("SOVEREIGN CORE CRYPTOGRAPHIC POSTURE VERIFICATION HARNESS SUITE")
    print("="*70)
    matrix = [
        ("SWAP_DELTA", fault_swap, "swap"),
        ("NETWORK_DELTA", fault_net, "eth0"),
        ("STORAGE_DELTA", fault_storage, "/dev/vda"),
        ("CONTROL_CLEAN", fault_none, "Key materials processed. Executing deterministic cleanup.")
    ]
    overall_pass = True
    for name, fault_func, expected_string in matrix:
        code, out, err = run_isolated_axis(name, fault_func)
        is_trip = name != "CONTROL_CLEAN"
        msg_present = expected_string in err
        wipe_before_kill = "Cryptographic allocations zeroed" in err and "Transmitting SIGKILL" in err
        if is_trip:
            killed_by_sigkill = (code == -9)
            pass_check = msg_present and killed_by_sigkill and wipe_before_kill
            print(f"Axis [{name:<13}] -> Exit Code: {code:<5} | Correct root cause: {msg_present} | SIGKILL confirmed: {killed_by_sigkill} | Wipe-before-kill: {wipe_before_kill}")
        else:
            pass_check = (code == 0) and msg_present
            print(f"Axis [{name:<13}] -> Exit Code: {code:<5} | Clean completion msg: {msg_present} | Clean exit: {code==0}")
        if not pass_check:
            overall_pass = False
            print(f"[FAIL DETAIL for {name}] stderr:\n{err}")

    print()
    if overall_pass:
        print("[VERIFICATION MATCH] All 4 independent dimensions executed to specification. Core secure.")
        sys.exit(0)
    else:
        print("[VERIFICATION FAILURE] One or more axes did not meet the asserted contract.")
        sys.exit(1)
