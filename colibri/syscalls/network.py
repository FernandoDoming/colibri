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
from colibri.utils.network import ql_bin_to_ip, random_ipv4, random_private_ipv4
from colibri.core.const import CATEGORY_NETWORK

# -----------------------------------------------------------------
def syscall_socket(ql: Qiling, socket_domain, socket_type, socket_protocol):
    idx = next((i for i in range(NR_OPEN) if ql.os.fd[i] is None), -1)
    regreturn = idx

    if idx != -1:
        # ql_socket.open should use host platform based socket_type.
        try:
            emu_socket_value = socket_type
            emu_socket_type = socket_type_mapping(socket_type, ql.arch.type, ql.os.type)
            socket_type = getattr(socket, emu_socket_type)
            ql.log.debug(f'Convert emu_socket_type {emu_socket_type}:{emu_socket_value} to host platform based socket_type {emu_socket_type}:{socket_type}')

        except AttributeError:
            ql.log.error(f'Cannot convert emu_socket_type {emu_socket_type}:{emu_socket_value} to host platform based socket_type')
            raise

        except Exception:
            ql.log.error(f'Cannot convert emu_socket_type {emu_socket_value} to host platform based socket_type')
            raise

        mock_socket_type = socket_type
        mock_socket_proto = socket_protocol
        if os.geteuid() != 0 and socket_type == socket.SOCK_RAW and not ql.hb.options.get("network", False):
            # non root users (or bins without cap_net_raw permissions) cannot open RAW sockets
            # as such, change the type to something else if network emulation is enabled
            mock_socket_type = socket.SOCK_DGRAM
            mock_socket_proto = 0

        try:
            if ql.verbose >= QL_VERBOSE.DEBUG:  # set REUSEADDR options under debug mode
                ql.os.fd[idx] = ql_socket.open(
                    socket_domain,
                    mock_socket_type,
                    mock_socket_proto,
                    (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                )
            else:
                ql.os.fd[idx] = ql_socket.open(
                    socket_domain,
                    mock_socket_type,
                    mock_socket_proto
                )
        except OSError as e:  # May raise error: Protocol not supported
            ql.log.debug(f'{e}: {socket_domain=}, {socket_type=}, {socket_protocol=}')
            regreturn = -1

    socket_type = socket_type_mapping(socket_type, ql.arch.type, ql.os.type)
    socket_domain = socket_domain_mapping(socket_domain, ql.arch.type, ql.os.type)
    ql.log.debug("socket(%s, %s, %s) = %d" % (socket_domain, socket_type, socket_protocol, regreturn))

    ql.hb.log_syscall(
        name = "socket",
        args = {
            "socket_domain": socket_domain,
            "socket_type": socket_type,
            "socket_protocol": socket_protocol
        },
        retval = regreturn,
        extra = {
            "mocked_socket_type": mock_socket_type,
            "mocked_socket_protocol": mock_socket_proto
        }
    )

    return regreturn


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
            else:
                regreturn = send_len

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


def syscall_sendto(
    ql: Qiling,
    sockfd: int,
    sendto_buf,
    sendto_len,
    sendto_flags,
    sendto_addr,
    sendto_addrlen
):
    regreturn = 0
    if sockfd not in range(NR_OPEN):
        regreturn = -1

    s = ql.os.fd[sockfd]
    if s is None:
        regreturn = -1

    if regreturn != -1:
        # For x8664, sendto() is called finally when calling send() in TCP communications
        if s.socktype == socket.SOCK_STREAM:
            return syscall_send(ql, sockfd, sendto_buf, sendto_len, sendto_flags)

        try:
            tmp_buf = ql.mem.read(sendto_buf, sendto_len)

            if ql.arch.type== QL_ARCH.X8664:
                data = ql.mem.read(sendto_addr, 8)
            else:
                data = ql.mem.read(sendto_addr, sendto_addrlen)

            sin_family, = struct.unpack("<h", data[:2])
            port, host = struct.unpack(">HI", data[2:8])
            host = ql_bin_to_ip(host)

            if sin_family == socket.AF_UNIX:
                path = data[2:].split(b'\x00')[0]
                path = ql.os.path.transform_to_real_path(path.decode())

                ql.log.debug("sendto() path is " + str(path))
                regreturn = s.sendto(bytes(tmp_buf), sendto_flags, path)
            else:
                ql.log.debug("sendto() addr is %s:%d" % (host, port))
                if ql.hb.options.get("network", False):
                    regreturn = s.sendto(bytes(tmp_buf), sendto_flags, (host, port))
                else:
                    regreturn = sendto_len


        except:
            ql.log.debug(sys.exc_info()[0])

            if ql.verbose >= QL_VERBOSE.DEBUG:
                raise

    ql.hb.log_syscall(
        name = "sendto",
        args = {
            "fd": sockfd,
            "len": sendto_len,
            "flags": sendto_flags,
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
def syscall_accept(ql: Qiling, accept_sockfd, accept_addr, accept_addrlen):
    def inet_addr(ip):
        ret = b''
        tmp = ip.split('.')
        if len(tmp) != 4:
            return ret
        for i in tmp[ : : -1]:
            ret += bytes([int(i)])
        return ret

    s = ql.os.fd[accept_sockfd]
    conn = None
    address = (None, None)
    if ql.hb.options.get("network", False):
        try:
            conn, address = s.accept()
            if conn is None:
                regreturn = -1


        except:
            if ql.verbose >= QL_VERBOSE.DEBUG:
                raise
            regreturn = -1
    else:
        # Doesn't really matter
        conn = ql_socket.open(socket.AF_INET, socket.SOCK_STREAM)
        address = (random_ipv4(), random.randint(0, 65535))

    idx = next((i for i in range(NR_OPEN) if ql.os.fd[i] is None), -1)
    regreturn = idx
    if idx != -1:
        ql.os.fd[idx] = conn

    if ql.code == None and accept_addr != 0 and accept_addrlen != 0:
        tmp_buf = ql.pack16(conn.family)
        tmp_buf += ql.pack16(address[1])
        tmp_buf += inet_addr(address[0])
        tmp_buf += b'\x00' * 8
        ql.mem.write(accept_addr, tmp_buf)
        ql.mem.write_ptr(accept_addrlen, 16, 4)

    extra = {}
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
        name = "accept",
        args = {
            "fd": accept_sockfd,
            "accept_addr": accept_addr,
            "accept_addrlen": accept_addrlen,
        },
        retval = regreturn,
        extra = extra
    )
    return regreturn

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


def syscall_recvfrom(
    ql: Qiling,
    sockfd: int,
    buf: int,
    length: int,
    flags: int,
    addr: int,
    addrlen: int
):
    regreturn = 0
    if sockfd not in range(NR_OPEN):
        regreturn = -1

    sock = ql.os.fd[sockfd]
    if sock is None:
        regreturn = -1

    if regreturn != -1:
        # For x8664, recvfrom() is called finally when calling recv() in TCP communications
        if sock.socktype == socket.SOCK_STREAM:
            return syscall_recv(ql, sockfd, buf, length, flags)

        if ql.hb.options.get("network", False):
            tmp_buf, tmp_addr = sock.recvfrom(length, flags)
        else:
            tmp_buf = b""
            if hasattr(sock, "connected_ip") and hasattr(sock, "connected_port"):
                tmp_addr = (sock.connected_ip, sock.connected_port)
            else:
                tmp_addr = (random_ipv4(), random.randint(0, 65535))

        ql.log.debug("recvfrom() CONTENT: %s", tmp_buf)
        sin_family = int(sock.family)
        data = struct.pack("<h", sin_family)

        if sin_family == 1:
            ql.log.debug("recvfrom() path is " + tmp_addr)
            data += tmp_addr.encode()
        else:
            ql.log.debug("recvfrom() addr is %s:%d" % (tmp_addr[0], tmp_addr[1]))
            data += struct.pack(">H", tmp_addr[1])
            data += ipaddress.ip_address(tmp_addr[0]).packed
            addrlen = ql.mem.read_ptr(addrlen)
            data = data[:addrlen]

        ql.mem.write(addr, data)
        ql.mem.write(buf, tmp_buf)
        regreturn = len(tmp_buf)

    ql.hb.log_syscall(
        name = "recvfrom",
        args = {
            "fd": sockfd,
            "flags": flags,
        },
        retval = regreturn,
        extra = {
            "family": sock.family.name,
            "type": sock.socktype.name,
            "content": tmp_buf.decode("utf-8"),
            "recvfrom_addr_ip": tmp_addr[0],
            "recvfrom_addr_port": tmp_addr[1]
        }
    )
    return regreturn
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
                host = random_private_ipv4()
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
    regreturn = 0
    if sockfd not in range(NR_OPEN) or ql.os.fd[sockfd] is None:
        regreturn = -EBADF

    ql.hb.log_syscall(
        name = "setsockopt",
        args = {
            "sockfd": sockfd,
            "level": level,
            "optname": optname,
            "optval_addr": optval_addr,
            "optlen": optlen
        },
        retval = regreturn,
    )
    return regreturn

# -----------------------------------------------------------------
def syscall_getsockopt(ql: Qiling, sockfd, level, optname, optval_addr, optlen_addr):
    if sockfd not in range(NR_OPEN) or ql.os.fd[sockfd] is None:
        return -EBADF

    common_syscall_exit(ql)
    return 0