"""
run_host_monitors.py — runs XdrFileWatchdog and BpfSyscallWatcher
concurrently in separate threads, both pushing standardized alert dicts into
the same shared queue (xdr.core.alert_queue.ALERT_QUEUE), and drains that
queue in a third thread to prove both sources produce events simultaneously.
 
Must be run as root -- the eBPF kprobe requires CAP_SYS_ADMIN/CAP_BPF. The
watchdog side doesn't need root on its own, but running the whole script as
root is simplest since the eBPF half does.
 
Usage:
    sudo python3 run_host_monitors.py --watch-dir /tmp/xdr_watch_test
 
While running, in another terminal:
    touch /tmp/xdr_watch_test/somefile.txt      # exercises the watchdog thread
    sudo bpftool prog list                      # exercises the eBPF thread
"""
 
import argparse
import os
import queue
import threading
import time
 
from xdr.core.alert_queue import ALERT_QUEUE
from xdr.host.file_watchdog import XdrFileWatchdog
from xdr.host.ebpf_hooks import BpfSyscallWatcher
 
 
def run_ebpf_poll_loop(watcher: BpfSyscallWatcher, stop_event: threading.Event):
    """Runs in its own thread: just polls the perf buffer of an ALREADY
    constructed/attached BpfSyscallWatcher until stop_event is set.
 
    Deliberately does NOT construct the BPF program here. Building/attaching
    it involves BCC compiling and loading the program, which makes a burst of
    its own bpf() calls internally -- doing that from within a background
    thread rather than the main thread (where the whitelist is captured via
    os.getpid()) can cause those internal calls to show up under a PID that
    was never whitelisted, causing false self-alerts. Constructing the
    watcher in main() instead keeps setup and its self-noise under the same
    already-whitelisted PID.
    """
    while not stop_event.is_set():
        # short timeout so this loop notices stop_event promptly instead of
        # blocking indefinitely inside perf_buffer_poll()
        watcher.bpf.perf_buffer_poll(timeout=200)
 
 
def drain_queue(stop_event: threading.Event, seen_types: set, lock: threading.Lock):
    """Runs in its own thread: pulls alerts off the shared queue as they
    arrive from EITHER producer thread and prints them, tagging which
    detector type each one came from so simultaneity is visible in the log."""
    while not stop_event.is_set():
        try:
            alert = ALERT_QUEUE.get(timeout=0.5)
        except queue.Empty:
            continue
        with lock:
            seen_types.add(alert["type"])
        print(f"[QUEUE] {alert}")
 
 
def main():
    parser = argparse.ArgumentParser(description="Run host-side detectors concurrently.")
    parser.add_argument("--watch-dir", default="/tmp/xdr_watch_test",
                         help="Directory for the file watchdog to monitor.")
    parser.add_argument("--duration", type=int, default=0,
                         help="Auto-stop after N seconds (0 = run until Ctrl+C).")
    args = parser.parse_args()
 
    if os.geteuid() != 0:
        print("Error: this must be run as root (the eBPF kprobe requires CAP_SYS_ADMIN/CAP_BPF).")
        raise SystemExit(1)
 
    stop_event = threading.Event()
    seen_types: set = set()
    seen_types_lock = threading.Lock()
 
    # --- file watchdog: manages its own Observer thread internally ---
    fs_watchdog = XdrFileWatchdog(args.watch_dir)
    fs_watchdog.start()
    print(f"[main] file watchdog watching: {args.watch_dir}")
 
    # --- eBPF watcher: construct/attach HERE in the main thread (see the
    # docstring on run_ebpf_poll_loop for why), then hand it to a background
    # thread that only polls -- perf_buffer_poll() blocks, so it needs its
    # own thread, but building the program does not.
    ebpf_watcher = BpfSyscallWatcher()
    print(f"[main] eBPF watcher attached, whitelisted PIDs: {sorted(ebpf_watcher.whitelist)}")
 
    ebpf_thread = threading.Thread(
        target=run_ebpf_poll_loop, args=(ebpf_watcher, stop_event), name="ebpf-poll", daemon=True
    )
    ebpf_thread.start()
 
    # --- shared queue consumer ---
    consumer_thread = threading.Thread(
        target=drain_queue, args=(stop_event, seen_types, seen_types_lock),
        name="queue-consumer", daemon=True,
    )
    consumer_thread.start()
 
    print("\nBoth detectors running concurrently. Try, from another terminal:")
    print(f"  touch {args.watch_dir}/somefile.txt   (exercises the file watchdog)")
    print("  sudo bpftool prog list                (exercises the eBPF hook)")
    print("Ctrl+C to stop.\n")
 
    try:
        start = time.time()
        while True:
            time.sleep(0.5)
            if args.duration and (time.time() - start) >= args.duration:
                break
    except KeyboardInterrupt:
        pass
    finally:
        print("\n[main] stopping...")
        stop_event.set()
        fs_watchdog.stop()
        ebpf_thread.join(timeout=2)
        consumer_thread.join(timeout=2)
 
        with seen_types_lock:
            print(f"\nAlert types observed this run: {sorted(seen_types)}")
            file_side = any(t.startswith("file_") for t in seen_types)
            ebpf_side = any(t.startswith("ebpf_") for t in seen_types)
            print(f"File watchdog produced events:  {file_side}")
            print(f"eBPF watcher produced events:   {ebpf_side}")
            if file_side and ebpf_side:
                print("CONFIRMED: both modules produced queue events in this run.")
 
 
if __name__ == "__main__":
    main()
 