import os
import time
import gevent

from qiling import Qiling

# -----------------------------------------------------------------
def syscall_clock_nanosleep_time64(ql: Qiling, clk_id: int, flags: int, req: int, rem: int):
    return __sleep_common(ql, req, rem, True)

def syscall_nanosleep(ql: Qiling, req: int, rem: int):
    return __sleep_common(ql, req, rem)

def syscall_clock_nanosleep(ql: Qiling, clockid: int, flags: int, req: int, rem: int):
    return __sleep_common(ql, req, rem)

def __sleep_common(ql: Qiling, req: int, rem: int, force_timespec64: bool = False) -> int:
    if ql.hb.options.get("skip_sleep", True):
        return 0

    tv_sec_size = 8 if force_timespec64 else ql.arch.pointersize
    tv_nsec_size = ql.arch.pointersize

    tv_sec = None
    if force_timespec64:
        tv_sec = ql.unpack64(ql.mem.read(req, tv_sec_size))
    else:
        tv_sec = ql.unpack(ql.mem.read(req, tv_sec_size))

    tv_sec += ql.unpack(ql.mem.read(req + tv_sec_size, tv_nsec_size)) / 1000000000
    pid = os.getpid()
    syscalls = ql.hb.report["syscalls"]
    if not pid in syscalls:
        syscalls[pid] = []
    syscalls[pid].append({
        "name": "sleep",
        "args": {
            "tv_sec": tv_sec,
        },
        "return": 0
    })

    if ql.os.thread_management:
        def _sched_sleep(cur_thread):
            gevent.sleep(tv_sec)

        ql.emu_stop()
        ql.os.thread_management.cur_thread.sched_cb = _sched_sleep

        # FIXME: this seems to be incomplete
        th = ql.os.thread_management.cur_thread
    else:
        time.sleep(tv_sec)

    return 0