import os
import sys
import time
import struct
import socket
import random
import ipaddress

from unicorn.unicorn import UcError

from qiling import Qiling
from qiling.os.posix.filestruct import ql_socket
from qiling.const import QL_INTERCEPT, QL_VERBOSE, QL_ARCH
from qiling.os.posix.const_mapping import (
    socket_type_mapping, socket_level_mapping, socket_domain_mapping,
    socket_ip_option_mapping, socket_option_mapping
)
from qiling.os.posix.const import *
from qiling.os.posix.filestruct import ql_socket

from colibri.syscalls.common import common_syscall_exit
from colibri.utils.network import ql_bin_to_ip, random_ipv4
from colibri.core.const import CATEGORY_NETWORK

# -----------------------------------------------------------------
def syscall_connect(ql, connect_sockfd, connect_addr, connect_addrlen):
    sock_addr = ql.mem.read(connect_addr, connect_addrlen)
    family = ql.unpack16(sock_addr[ : 2])
    s = ql.os.fd[connect_sockfd]
    ip = ""
    sun_path = ""
    port = 0
    result = "mocked"

    try:
        if s.family == family:
            if s.family == socket.AF_UNIX:
                sun_path = sock_addr[2:].split(b"\x00")[0]
                sun_path = ql.os.path.transform_to_real_path(sun_path.decode())
                ql.log.debug("connect(%s) = %d" % (sun_path, regreturn))
                s.connect(sun_path)
                regreturn = 0

            elif s.family == socket.AF_INET:
                port, host = struct.unpack(">HI", sock_addr[2:8])
                ip = ql_bin_to_ip(host)
                s.connected_ip = ip
                s.connected_port = port
                if ql.hb.options.get("network", False):
                    try:
                        s.connect((ip, port))
                        result = "success"
                    except Exception:
                        result = "fail"

                # Even if connect fails, return 0 so execution continues
                regreturn = 0
            else:
                regreturn = -1
        else:
            regreturn = -1

        ql.hb.log_syscall(
            name = "connect",
            args = {
                "fd": connect_sockfd,
            },
            retval = regreturn,
            extra = {
                "host": ip,
                "port": port,
                "sun_path": sun_path,
                "family": s.family.name,
                "type": s.socktype.name,
                "resolution": result,
            }
        )

    except Exception:
        ql.log.info(sys.exc_info()[0])
        regreturn = -1

    finally:
        common_syscall_exit(ql)

    return regreturn

# -----------------------------------------------------------------
def syscall_send(ql, send_sockfd, send_buf, send_len, send_flags):
    regreturn = 0
    s = ql.os.fd[send_sockfd]
    if 0 <= send_sockfd < 1024 and s != 0:
        try:
            tmp_buf = ql.mem.read(send_buf, send_len)
            ql.log.debug("send() CONTENT:")
            ql.log.debug("%s" % str(tmp_buf))
            ql.log.debug("send() flag is " + str(send_flags))
            ql.log.debug("send() len is " + str(send_len))

            if ql.hb.options.get("network", False):
                try:
                    regreturn = s.send(
                        bytes(tmp_buf), send_flags
                    )
                except Exception:
                    pass

            ql.hb.add_report_info(
                category = CATEGORY_NETWORK,
                subcategory = "sent_data",
                data = {
                    "fd": send_sockfd,
                    "ip": s.connected_ip,
                    "port": s.connected_port,
                    "family": s.family.name,
                    "type": s.socktype.name,
                    "data": tmp_buf.decode("utf-8"),
                }
            )

            ql.hb.log_syscall(
                name = "send",
                args = {
                    "fd": send_sockfd,
                },
                retval = regreturn,
                extra = {
                    "ip": s.connected_ip,
                    "port": s.connected_port,
                    "family": s.family.name,
                    "type": s.socktype.name,
                    "data": tmp_buf.decode("utf-8"),
                }
            )

        except Exception:
            ql.log.info(sys.exc_info()[0])
            if ql.verbose >= QL_VERBOSE.DEBUG:
                raise

        finally:
           common_syscall_exit(ql)
    else:
        regreturn = -1
    return regreturn

# -----------------------------------------------------------------
def syscall_bind_onexit(ql: Qiling, bind_fd, bind_addr, bind_addrlen, retval: int):
    if ql.arch.type == QL_ARCH.X8664:
        data = ql.mem.read(bind_addr, 8)
    else:
        data = ql.mem.read(bind_addr, bind_addrlen)

    sin_family = ql.unpack16(data[:2]) or ql.os.fd[bind_fd].family
    port, host = struct.unpack(">HI", data[2:8])
    host = ql_bin_to_ip(host)

    path = None
    if sin_family == socket.AF_UNIX:
        path = data[2:].split(b'\x00')[0]
        path = ql.os.path.transform_to_real_path(path.decode())

    s = ql.os.fd[bind_fd]
    if isinstance(s, ql_socket):
        s.binded_ip   = host
        s.binded_port = port

    ql.hb.log_syscall(
        name = "bind",
        args = {
            "fd": bind_fd,
        },
        retval = retval,
        extra = {
            "host": host,
            "port": port,
            "family": s.family.name,
            "type": s.socktype.name,
            "path": path,
        }
    )

# -----------------------------------------------------------------
def syscall_listen_onexit(ql: Qiling, sockfd: int, backlog: int, retval: int):
    extra = {}
    s = ql.os.fd[sockfd]
    if (
        isinstance(s, ql_socket) and
        hasattr(s, "binded_ip") and
        hasattr(s, "binded_port")
    ):
        extra = {
            "host": s.binded_ip,
            "port": s.binded_port,
            "family": s.family.name,
            "type": s.socktype.name,
        }

    ql.hb.log_syscall(
        name = "listen",
        args = {
            "fd": sockfd,
        },
        retval = retval,
        extra = extra
    )

# -----------------------------------------------------------------
def syscall_accept_onenter(ql: Qiling, accept_sockfd, accept_addr, accept_addrlen):
    ql.hb.log_syscall(
        name = "accept",
        args = {
            "fd": accept_sockfd,
        },
    )

# -----------------------------------------------------------------
def syscall_recv(ql, sockfd: int, buf: int, length: int, flags: int):
    if sockfd not in range(NR_OPEN):
        return -1

    sock = ql.os.fd[sockfd]
    if sock is None:
        return -1

    content = b""
    if ql.hb.options.get("network", False):
        try:
            content = sock.recv(length, flags)
        except Exception:
            pass
    else:
        # Fake a network delay
        time.sleep(random.randint(100, 500) / 1000.0)

    if content:
        ql.log.debug("recv() CONTENT:")
        ql.log.debug("%s" % content)

    ql.mem.write(buf, content)

    ql.hb.log_syscall(
        name = "recv",
        args = {
            "fd": sockfd,
        },
        retval = len(content),
        extra = {
            "family": sock.family.name,
            "type": sock.socktype.name,
            "content": content.decode("utf-8"),
        }
    )
    common_syscall_exit(ql)
    return len(content)

# -----------------------------------------------------------------
def syscall_getsockname(ql: Qiling, sockfd: int, addr: int, addrlenptr: int):
    if 0 <= sockfd < NR_OPEN:
        socket = ql.os.fd[sockfd]

        if isinstance(socket, ql_socket):
            host, port, resolution = None, None, None
            if ql.hb.options.get("network", False):
                host, port = socket.getpeername()
                resolution = "success"
            else:
                host = random_ipv4()
                port = random.randint(0, 65535)
                resolution = "mocked"

            data = struct.pack("<h", int(socket.family))
            data += struct.pack(">H", port)
            data += ipaddress.ip_address(host).packed

            addrlen = ql.mem.read_ptr(addrlenptr)

            ql.mem.write(addr, data[:addrlen])
            regreturn = 0
        else:
            regreturn = -EPERM
    else:
        regreturn = -EPERM

    ql.hb.log_syscall(
        name = "getsockname",
        args = {
            "sockfd": sockfd,
        },
        retval = regreturn,
        extra = {
            "family": socket.family.name,
            "type": socket.socktype.name,
            "resolution": resolution,
            "resolved_host": host,
            "resolved_port": port,
        }
    )
    ql.log.debug("getsockname(%d, 0x%x, 0x%x) = %d" % (sockfd, addr, addrlenptr, regreturn))
    common_syscall_exit(ql)
    return

# -----------------------------------------------------------------
def syscall_setsockopt(ql: Qiling, sockfd, level, optname, optval_addr, optlen):
    if sockfd not in range(NR_OPEN) or ql.os.fd[sockfd] is None:
        return -EBADF

    regreturn = 0
    common_syscall_exit(ql)
    return regreturn

# -----------------------------------------------------------------
def syscall_getsockopt(ql: Qiling, sockfd, level, optname, optval_addr, optlen_addr):
    if sockfd not in range(NR_OPEN) or ql.os.fd[sockfd] is None:
        return -EBADF

    common_syscall_exit(ql)
    return 0