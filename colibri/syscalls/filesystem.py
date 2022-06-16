import os
import sys
import traceback

from qiling import Qiling
from colibri.core.const import CATEGORY_FILESYSTEM
from colibri.syscalls.common import common_syscall_exit

from qiling.os.posix.const import *
from qiling.os.posix.filestruct import ql_socket

# -----------------------------------------------------------------
def syscall_write(ql: Qiling, fd, buf, count):
    regreturn = -1
    try:
        if fd not in range(NR_OPEN):
            return -EBADF

        f = ql.os.fd[fd]

        if f is None:
            return -EBADF

        try:
            data = ql.mem.read(buf, count)
        except:
            regreturn = -1
        ql.log.debug(f'write() CONTENT: {bytes(data)}')

        if hasattr(f, 'write'):
            if not isinstance(f, ql_socket) or ql.hb.options.get("network", False):
                f.write(data)
            regreturn = count
        else:
            ql.log.warning(f'write failed since fd {fd:d} does not have a write method')
            regreturn = -1

        filename = fd
        if hasattr(f, "name"):
            filename = f.name
        if isinstance(f, ql_socket):
            filename = f"socket({f.connected_ip}:{f.connected_port})"

        fs = ql.hb.report[CATEGORY_FILESYSTEM]
        pid = os.getpid()
        if not pid in fs:
            fs[pid] = {}
        if not "write" in fs[pid]:
            fs[pid]["write"] = {}
        if not filename in fs[pid]["write"]:
            fs[pid]["write"][filename] = ""
        fs[pid]["write"][filename] += data.decode("utf-8")
        ql.hb.report[CATEGORY_FILESYSTEM] = fs

        ql.hb.log_syscall(
            name = "write",
            args = {
                "fd": fd,
                "filename": filename,
                "buf": data.decode("utf-8"),
                "count": count,
            },
            retval = regreturn
        )
    except Exception:
        ql.log.info(traceback.format_exc())

    finally:
        common_syscall_exit(ql)

    return regreturn

# -----------------------------------------------------------------
def syscall_open_onenter(ql: Qiling, filename: int, flags: int, mode: int):
    try:
        path = ql.os.utils.read_cstring(filename)
        ql.hb.add_report_info(
            category = CATEGORY_FILESYSTEM,
            subcategory = "open",
            data = {
                "path": path,
                "flags": flags,
                "mode": mode,
            }
        )
    except Exception:
        ql.log.info(traceback.format_exc())

def syscall_open_onexit(ql: Qiling, filename: int, flags: int, mode: int, retval: int):
    try:
        path = ql.os.utils.read_cstring(filename)
        ql.hb.log_syscall(
            name = "open",
            args = {
                "path": path,
                "flags": flags,
                "mode": mode,
            },
            retval = retval
        )
    except Exception:
        ql.log.info(traceback.format_exc())