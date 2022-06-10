import os
import sys

from qiling import Qiling

# -----------------------------------------------------------------
def write_onenter(ql: Qiling, fd, buf, count):
    try:
        data = ql.mem.read(buf, count)
        filename = ql.os.fd[fd].name

        fs = ql.hb.report["filesystem"]
        if not "write" in fs:
            fs["write"] = {}
        if not filename in fs["write"]:
            fs["write"][filename] = ""
        fs["write"][filename] += data.decode("utf-8")
        ql.hb.report["filesystem"] = fs
    except Exception:
        ql.log.info(sys.exc_info()[0])

# -----------------------------------------------------------------
def open_onenter(ql: Qiling, filename: int, flags: int, mode: int):
    try:
        path = ql.os.utils.read_cstring(filename)

        fs = ql.hb.report["filesystem"]
        if not "open" in fs:
            fs["open"] = []
        fs["open"].append({
            "path": path,
            "flags": flags,
            "mode": mode,
        })
        ql.hb.report["filesystem"] = fs
    except Exception:
        ql.log.info(sys.exc_info()[0])

def open_onexit(ql: Qiling, filename: int, flags: int, mode: int, retval: int):
    try:
        path = ql.os.utils.read_cstring(filename)
        syscalls = ql.hb.report["syscalls"]
        caller_pid = os.getpid()
        if caller_pid not in syscalls:
            syscalls[caller_pid] = []
        syscalls[caller_pid].append({
            "name": "open",
            "args": {
                "path": path,
                "flags": flags,
                "mode": mode,
            },
            "return": retval,
        })
        ql.hb.report["syscalls"] = syscalls
    except Exception:
        ql.log.info(sys.exc_info()[0])