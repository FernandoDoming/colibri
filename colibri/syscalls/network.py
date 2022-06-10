import sys
import struct
import random
import ipaddress

from qiling import Qiling
from qiling.os.posix.filestruct import ql_socket
from qiling.const import QL_INTERCEPT, QL_VERBOSE
from qiling.os.posix.const import NR_OPEN, EPERM

from colibri.utils.network_utils import ql_bin_to_ip, random_ipv4

# -----------------------------------------------------------------
def syscall_connect(ql, connect_sockfd, connect_addr, connect_addrlen):
    AF_UNIX = 1
    AF_INET = 2
    sock_addr = ql.mem.read(connect_addr, connect_addrlen)
    family = ql.unpack16(sock_addr[ : 2])
    s = ql.os.fd[connect_sockfd]
    ip = b''
    sun_path = b''
    port = 0
    result = "mocked"

    try:
        if s.family == family:
            if s.family == AF_UNIX:
                sun_path = sock_addr[2:].split(b"\x00")[0]
                sun_path = ql.os.path.transform_to_real_path(sun_path.decode())
                ql.log.debug("connect(%s) = %d" % (sun_path, regreturn))
                s.connect(sun_path)
                regreturn = 0

            elif s.family == AF_INET:
                port, host = struct.unpack(">HI", sock_addr[2:8])
                ip = ql_bin_to_ip(host)

                if ql.hb.options.get("network", False):
                    try:
                        s.connect((ip, port))
                        result = "success"
                    except Exception:
                        result = "fail"

                network = ql.hb.report["network"]
                if "sockets" not in network:
                    network["sockets"] = []
                network["sockets"].append({
                    "fd": connect_sockfd,
                    "ip": ip,
                    "port": port,
                    "result": result,
                })
                ql.hb.report["network"] = network
                # Even if connect fails, return 0 so execution continues
                regreturn = 0
            else:
                regreturn = -1
        else:
            regreturn = -1
    except Exception:
        ql.log.info(sys.exc_info()[0])
        regreturn = -1
    return regreturn

# -----------------------------------------------------------------
def syscall_send(ql, send_sockfd, send_buf, send_len, send_flags):
    regreturn = 0
    if 0 <= send_sockfd < 1024 and ql.os.fd[send_sockfd] != 0:
        try:
            tmp_buf = ql.mem.read(send_buf, send_len)
            ql.log.debug("send() CONTENT:")
            ql.log.debug("%s" % str(tmp_buf))
            ql.log.debug("send() flag is " + str(send_flags))
            ql.log.debug("send() len is " + str(send_len))

            if ql.hb.options.get("network", False):
                try:
                    regreturn = ql.os.fd[send_sockfd].send(
                        bytes(tmp_buf), send_flags
                    )
                except Exception:
                    pass

            network = ql.hb.report["network"]
            if "sent_data" not in network:
                network["sent_data"] = []
            network["sent_data"].append({
                "fd": send_sockfd,
                "data": tmp_buf.decode("utf-8"),
            })
            ql.hb.report["network"] = network
        except Exception:
            ql.log.info(sys.exc_info()[0])
            if ql.verbose >= QL_VERBOSE.DEBUG:
                raise
    else:
        regreturn = -1
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

    if content:
        ql.log.debug("recv() CONTENT:")
        ql.log.debug("%s" % content)

    ql.mem.write(buf, content)
    return len(content)

# -----------------------------------------------------------------
def syscall_getsockname(ql: Qiling, sockfd: int, addr: int, addrlenptr: int):
    if 0 <= sockfd < NR_OPEN:
        socket = ql.os.fd[sockfd]

        if isinstance(socket, ql_socket):
            host, port = None, None
            if ql.hb.options.get("network", False):
                host, port = socket.getpeername()
            else:
                host = random_ipv4()
                port = random.randint(0, 65535)

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

    ql.log.debug("getsockname(%d, 0x%x, 0x%x) = %d" % (sockfd, addr, addrlenptr, regreturn))
    return 