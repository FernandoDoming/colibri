import os
import sys

from qiling import Qiling
from colibri.core.const import CATEGORY_FILESYSTEM

# -----------------------------------------------------------------
def write_onenter(ql: Qiling, fd, buf, count):
    try:
        data = ql.mem.read(buf, count)
        filename = ql.os.fd[fd].name

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
    except Exception:
        ql.log.info(sys.exc_info()[0])

# -----------------------------------------------------------------
def open_onenter(ql: Qiling, filename: int, flags: int, mode: int):
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
        ql.log.info(sys.exc_info()[0])

def open_onexit(ql: Qiling, filename: int, flags: int, mode: int, retval: int):
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
        ql.log.info(sys.exc_info()[0])