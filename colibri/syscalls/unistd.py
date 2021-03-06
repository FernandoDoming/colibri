import os
import sys
import time
from qiling import Qiling
from qiling.const import QL_ARCH, QL_OS
from multiprocessing import Process

from qiling.os.windows.windows import QlOsWindows
from colibri.syscalls.common import common_syscall_exit
from colibri.syscalls.const import *
from colibri.utils.mem import read_str_array

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
            ql.hb.report_new_child(regreturn)

        if ql.os.thread_management:
            ql.emu_stop()

        if regreturn:
            caller_pid = os.getpid()
            ql.hb.log_syscall(
                name = "vfork",
                args = {},
                retval = regreturn
            )

    except Exception:
        # After stopping execution and killing children
        # BrokenPipeErrors are expected if the function has passed
        # the initial if statement and tries to log the syscall
        ql.log.debug(sys.exc_info()[0])

    finally:
        common_syscall_exit(ql)

    return regreturn

# -----------------------------------------------------------------
def syscall_fork(ql: Qiling):
    return syscall_vfork(ql)

# -----------------------------------------------------------------
def syscall_clone_onexit(
    ql: Qiling, flags: int, child_stack: int,
    parent_tidptr: int, newtls: int, child_tidptr: int, retval: int
):
    if retval != 0:
        ql.hb.report_new_child(retval)
        ql.hb.log_syscall(
            name = "clone",
            args = {
                "flags": flags,
                "child_stack": child_stack,
                "parent_tidptr": parent_tidptr,
                "newtls": newtls,
                "child_tidptr": child_tidptr,
            },
            retval = retval
        )
    common_syscall_exit(ql)

# -----------------------------------------------------------------
def syscall_execve_onenter(ql: Qiling, pathname: int, argv: int, envp: int):
    file_path = ql.os.utils.read_cstring(pathname)
    real_path = ql.os.path.transform_to_real_path(file_path)

    args = [s for s in read_str_array(ql, argv)]

    env = {}
    for s in read_str_array(ql, envp):
        k, _, v = s.partition('=')
        env[k] = v

    ql.hb.log_syscall(
        name = "execve",
        args = {
            "pathname": real_path,
            "argv": args,
            "envp": env,
        }
    )

# -----------------------------------------------------------------
def syscall_exit_onenter(ql: Qiling, status: int):
    ql.hb.log_syscall(
        name = "exit",
        args = {
            "status": status,
        }
    )
    ql.hb.report_exit(status)

def syscall_exit_group_onenter(ql: Qiling, status: int):
    ql.hb.log_syscall(
        name = "exit_group",
        args = {
            "status": status,
        }
    )
    ql.hb.report_exit(status)

# -----------------------------------------------------------------
def syscall__newselect(ql: Qiling, nfds: int, readfds: int, writefds: int, exceptfds: int, timeout: int):
    common_syscall_exit(ql)
    return 1

# -----------------------------------------------------------------
def syscall_prctl(ql: Qiling, option: int, arg2: int, arg3: int, arg4: int, arg5: int):
    retval = 0

    args = {
        "option": PR_CONSTANT_NAMES.get(option, option)
    }
    if option == PR_SET_NAME:
        args["process_name"] = ql.os.utils.read_cstring(arg2)

    ql.hb.log_syscall(
        name = "prctl",
        args = args,
        retval = retval
    )
    return retval

# -----------------------------------------------------------------
def syscall_setsid_onexit(ql: Qiling, retval: int):
    ql.hb.log_syscall(
        name = "setsid",
        retval = retval
    )
