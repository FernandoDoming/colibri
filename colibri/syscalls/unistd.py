import os
import sys
from qiling import Qiling
from qiling.const import QL_ARCH, QL_OS
from multiprocessing import Process

from qiling.os.windows.windows import QlOsWindows

# -----------------------------------------------------------------
def syscall_vfork(ql: Qiling):
    regreturn = -1
    if not ql.hb.running.value:
        return regreturn

    try:
        if isinstance(ql.os, QlOsWindows):
            try:
                pid = Process() 
                pid = 0
            except:
                pid = -1
        else:
            pid = os.fork()

        ql.log.debug("vfork() = %d" % (pid))
        regreturn = pid
        if pid == 0:
            ql.os.child_processes = True

        if regreturn != 0:
            ql.hb.pids.append(regreturn)

        if ql.os.thread_management:
            ql.emu_stop()

        if regreturn:
            caller_pid = os.getpid()
            # Shared dicts are a bit special and are not updated
            # if not done like this
            # https://stackoverflow.com/a/48646169
            syscalls = ql.hb.report["syscalls"]
            if caller_pid not in syscalls:
                syscalls[caller_pid] = []
            syscalls[caller_pid].append({
                "name": "vfork",
                "return": regreturn,
            })
            ql.hb.report["syscalls"] = syscalls

    except Exception:
        # After stopping execution and killing children
        # BrokenPipeErrors are expected if the function has passed
        # the initial if statement and tries to log the syscall
        ql.log.debug(sys.exc_info()[0])

    finally:
        if not ql.hb.running.value:
            sys.exit(0)

    return regreturn

# -----------------------------------------------------------------
def syscall_fork(ql: Qiling):
    return syscall_vfork(ql)