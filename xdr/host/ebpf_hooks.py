"""
ebpf_hooks.py — eBPF kprobe on __sys_bpf, surfaced via a BCC perf ring buffer.

Watches for any process invoking the bpf() syscall and alerts on it, except
for: (1) a static whitelist of this script's own PID and its parent shell's
PID, and (2) any process that is a descendant of this one -- since BCC can
spawn short-lived internal helper processes (for compilation, symbol
resolution, etc.) that share our comm name but get their own unpredictable
PID, which no static whitelist could cover in advance.
"""

import argparse
import ctypes as ct
import os
import sys
import time
from typing import Set

from bcc import BPF

from xdr.core.alert_queue import push_alert
from xdr.core.events import SecurityEvent, Vector
from xdr.core.event_bus import ENGINE


HOOK_SYMBOL = "__sys_bpf"

BPF_PROGRAM = r"""
#include <linux/sched.h>

struct bpf_call_event_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

int on_sys_bpf(struct pt_regs *ctx) {
    struct bpf_call_event_t event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""


class BpfCallEvent(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("comm", ct.c_char * 16),
    ]


class BpfSyscallWatcher:
    def __init__(self, whitelist: Set[int] = None):
        self.whitelist: Set[int] = whitelist or set()
        self.whitelist.add(os.getpid())
        self.whitelist.add(os.getppid())

        self.bpf = BPF(text=BPF_PROGRAM)
        self.bpf.attach_kprobe(event=HOOK_SYMBOL, fn_name="on_sys_bpf")

        self.bpf["events"].open_perf_buffer(self._handle_event)

    def _is_descendant_of_self(self, pid: int) -> bool:
        """Walk pid's parent chain via /proc and check whether this process
        appears as an ancestor -- catches BCC-spawned helper processes that
        a static PID whitelist can't predict in advance."""
        self_pid = os.getpid()
        current = pid
        seen = set()

        while current not in (0, 1) and current not in seen:
            seen.add(current)
            if current == self_pid:
                return True
            try:
                with open(f"/proc/{current}/stat") as f:
                    fields = f.read().rsplit(")", 1)[1].split()
                ppid = int(fields[1])
            except (FileNotFoundError, ProcessLookupError, IndexError, ValueError):
                return False
            current = ppid

        return False

    def _handle_event(self, cpu, data, size):
        event = ct.cast(data, ct.POINTER(BpfCallEvent)).contents
        pid = event.pid
        comm = event.comm.decode("utf-8", errors="replace")

        if pid in self.whitelist or self._is_descendant_of_self(pid):
            return

        push_alert(
            alert_type="ebpf_unexpected_bpf_syscall",
            src=f"pid={pid} comm={comm!r}",
            severity="high",
        )

        ENGINE.publish_threadsafe(SecurityEvent(
            vector = Vector.KERNEL,
            event_type="ebpf_unexpected_bpf_syscall",
            src=f"pid={pid} comm={comm!r}",
            severity =4,
            metadata = {"pid": pid, "comm": comm},
        ))

        print(
            f"[ALERT] Unexpected bpf() syscall: pid={pid} comm={comm!r} "
            f"at {time.strftime('%Y-%m-%d %H:%M:%S')}"
        )

    def run(self):
        print(f"Hooked {HOOK_SYMBOL}. Whitelisted PIDs: {sorted(self.whitelist)}")
        print("Watching for bpf() syscalls from any other process. Ctrl+C to stop.\n")
        try:
            while True:
                self.bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            print("\nStopped.")


def main():
    parser = argparse.ArgumentParser(
        description="Alert on any process (other than this one) invoking the bpf() syscall."
    )
    parser.add_argument("--extra-whitelist", type=int, nargs="*", default=[])
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Error: this must be run as root (kprobes require CAP_SYS_ADMIN/CAP_BPF).")
        sys.exit(1)

    watcher = BpfSyscallWatcher(whitelist=set(args.extra_whitelist))
    watcher.run()


if __name__ == "__main__":
    main()
