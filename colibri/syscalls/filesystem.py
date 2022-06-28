import os
import pathlib
import traceback

from qiling import Qiling
from colibri.core.const import CATEGORY_FILESYSTEM
from colibri.syscalls.common import common_syscall_exit

from qiling.os.posix.const import *
from qiling.os.posix.filestruct import ql_socket
from qiling.os.posix.const_mapping import ql_open_flag_mapping
from qiling.exception import QlSyscallError

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
        extra = {}
        if hasattr(f, "name"):
            filename = f.name
        if isinstance(f, ql_socket):
            filename = f"socket({f.connected_ip}:{f.connected_port})"
            extra = {
                "ip": f.connected_ip,
                "port": f.connected_port,
                "family": f.family.name,
                "type": f.socktype.name,
                "data": data.decode("utf-8"),
            }

        ql.hb.log_syscall(
            name = "write",
            args = {
                "fd": fd,
                "filename": filename,
                "buf": data.decode("utf-8"),
                "count": count,
            },
            retval = regreturn,
            extra = extra
        )
    except Exception:
        ql.log.info(traceback.format_exc())

    finally:
        common_syscall_exit(ql)

    return regreturn

# -----------------------------------------------------------------
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

# -----------------------------------------------------------------
def syscall_readlink(ql: Qiling, path_name: int, path_buff: int, path_buffsize: int):
    pathname = ql.os.utils.read_cstring(path_name)
    # pathname = str(pathname, 'utf-8', errors="ignore")
    real_path = ql.os.path.transform_to_link_path(pathname)
    relative_path = ql.os.path.transform_to_relative_path(pathname)

    if not os.path.exists(real_path):
        regreturn = -1

    elif relative_path == r'/proc/self/exe':
        localpath = os.path.abspath(ql.path)
        if localpath.startswith(ql.rootfs):
            localpath = localpath.replace(ql.rootfs, "")
        localpath = bytes(localpath, 'utf-8') + b'\x00'

        ql.mem.write(path_buff, localpath)
        regreturn = len(localpath) - 1

    else:
        regreturn = 0

    ql.hb.log_syscall(
        name = "readlink",
        args = {
            "pathname": pathname,
        },
        retval = regreturn
    )

    ql.log.debug("readlink(%s, 0x%x, 0x%x) = %d" % (relative_path, path_buff, path_buffsize, regreturn))
    return regreturn


# -----------------------------------------------------------------
def syscall_unlink(ql: Qiling, pathname: int):
    file_path = ql.os.utils.read_cstring(pathname)
    real_path = ql.os.path.transform_to_real_path(file_path)

    regreturn = 0
    # Don't actually delete anything
    # opened_fds = [getattr(ql.os.fd[i], 'name', None) for i in range(NR_OPEN) if ql.os.fd[i] is not None]
    # path = pathlib.Path(real_path)

    # if any((real_path not in opened_fds, path.is_block_device(), path.is_fifo(), path.is_socket(), path.is_symlink())):
    #     try:
    #         os.unlink(real_path)
    #     except FileNotFoundError:
    #         ql.log.debug('No such file or directory')
    #         regreturn = -1
    #     except:
    #         regreturn = -1
    #     else:
    #         regreturn = 0

    # else:
    #     regreturn = -1

    # ql.log.debug("unlink(%s) = %d" % (file_path, regreturn))

    ql.hb.log_syscall(
        name = "unlink",
        args = {
            "pathname": file_path,
        },
        retval = regreturn
    )

    return regreturn

# -----------------------------------------------------------------
def syscall_close_onexit(ql: Qiling, fd: int, retval: int):
    ql.hb.log_syscall(
        name = "close",
        args = {
            "fd": fd,
        },
        retval = retval
    )