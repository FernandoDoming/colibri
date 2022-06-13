import os
import json
import time
import random
import signal
import logging
import shutil

from ctypes import c_bool
from multiprocessing import Manager, Value

import qiling as qlapi
from qiling.const import QL_INTERCEPT, QL_VERBOSE
from qiling.os.posix.const import NR_OPEN

from colibri.syscalls.network import *
from colibri.syscalls.filesystem import *
from colibri.syscalls.time import *
from colibri.syscalls.unistd import *

from colibri.utils.cmdline import (
    blue, red, yellow, green, magenta, cyan,
)

from colibri.core.classes import dotdict, Singleton

LOG_FORMAT = "%(asctime)-15s [%(levelname)s] - %(message)s"
logging.basicConfig(format=LOG_FORMAT)
log = logging.getLogger("colibri.main")
log.setLevel(logging.INFO)

# -----------------------------------------------------------------
class Colibri(metaclass=Singleton):
    replaced_syscall = {
        "connect": syscall_connect,
        "send": syscall_send,
        "recv": syscall_recv,
        "getsockname": syscall_getsockname,
        "fork": syscall_fork,
        "vfork": syscall_vfork,
        "nanosleep": syscall_nanosleep,
        "clock_nanosleep": syscall_clock_nanosleep,
        "clock_nanosleep_time64": syscall_clock_nanosleep_time64,
    }
    on_enter_hooks = {
        "write": write_onenter,
        "open": open_onenter,
    }
    on_exit_hooks = {
        "open": open_onexit,
        "execve": syscall_execve_onexit,
    }

    # ---------------------------------------
    def __init__(self, **kwargs) -> None:
        self.smm = Manager()
        self.pids = self.smm.list()
        self.report = self.smm.dict()
        self.running = Value(c_bool, False)
        self.report["syscalls"] = {}
        self.report["filesystem"] = {}
        self.report["network"] = {}

        self.options = dotdict(**kwargs)

    # ---------------------------------------
    def run(self, fpath, timeout = 10):
        self.ql = qlapi.Qiling(
            [fpath],
            self.options.rootfs,
            verbose=QL_VERBOSE.DEBUG if self.options.get("debug", False) else QL_VERBOSE.OFF
        )
        self.ql.hb = self
        self.set_hooks()
        self.reset_filesystem()

        # Doing this instead of Qiling's timeout because
        # Qiling's timeout does not stop forked children
        signal.signal(signal.SIGALRM, self.stop)
        signal.alarm(timeout)
        try:
            self.running = Value(c_bool, True)
            self.ql.run()
        except Exception:
            log.exception("Failed to run Qiling on sample %s", fpath)

        while self.running.value:
            time.sleep(1)

    # ---------------------------------------
    def set_hooks(self):
        for syscall_name, syscall_fn in self.replaced_syscall.items():
            self.ql.set_syscall(syscall_name, syscall_fn)

        for syscall_name, syscall_fn in self.on_enter_hooks.items():
            self.ql.os.set_syscall(syscall_name, syscall_fn, QL_INTERCEPT.ENTER)

        for syscall_name, syscall_fn in self.on_exit_hooks.items():
            self.ql.os.set_syscall(syscall_name, syscall_fn, QL_INTERCEPT.EXIT)

    # ---------------------------------------
    def stop(self, signum, frame):
        log.info("Colibri execution hit timeout. Stopping...")
        self.running = Value(c_bool, False)
        self.ql.emu_stop()

        with open(self.options.output_file, "w") as f:
            f.write(
                json.dumps(dict(self.report))
            )

        log.info(
            "Stopping pids %s", ", ".join([str(x) for x in self.pids])
        )
        for pid in self.pids:
            if pid == os.getpid():
                continue
            try:
                os.kill(pid, 9)
            except Exception:
                pass

    # ---------------------------------------
    def reset_filesystem(self):
        dirname    = os.path.dirname(__file__)
        rootfs_dir = os.path.join(dirname, "rootfs")
        log.info("Resetting filesystem to %s", rootfs_dir)
        if os.path.exists(self.options.rootfs):
            shutil.rmtree(self.options.rootfs)
        shutil.copytree(rootfs_dir, self.options.rootfs)

    # ---------------------------------------
    def log_syscall(self, name, args, retval, extra = {}):
        # Shared dicts are a bit special and are not updated
        # if not done like this
        # https://stackoverflow.com/a/48646169
        syscalls = self.report["syscalls"]
        caller_pid = os.getpid()
        if caller_pid not in syscalls:
            syscalls[caller_pid] = []
        syscalls[caller_pid].append({
            "name": name,
            "args": args,
            "return": retval,
            "extra": extra,
        })
        self.report["syscalls"] = syscalls

    # ---------------------------------------
    def add_report_info(self, category: str, subcategory: str, data: dict):
        catinfo = self.report[category]
        pid = os.getpid()
        if pid not in catinfo:
            catinfo[pid] = {}
        if subcategory not in catinfo[pid]:
            catinfo[pid][subcategory] = []
        catinfo[pid][subcategory].append(data)
        self.report[category] = catinfo

# -----------------------------------------------------------------
def main():
    import argparse
    print_banner()

    parser = argparse.ArgumentParser()
    default_rootfs = os.path.join(os.path.expanduser("~"), ".colibri", "rootfs")
    parser.add_argument(
        "-fs", "--rootfs",
        help = "Root directory to use as filesystem (default: %s)" % default_rootfs,
        default = default_rootfs
    )
    parser.add_argument(
        "-o", "--output",
        help = "Output file to write report to in JSON format (default: report.json)",
        default = "report.json"
    )
    parser.add_argument(
        "-t", "--timeout",
        help = "Max time to run the sample for (default: 60)",
        default = 10,
        type = int
    )
    parser.add_argument(
        "-n", "--network",
        help = "Use real networking",
        action = "store_true"
    )
    parser.add_argument(
        "--no-skip-sleep",
        help = "Don't skip sleep syscalls",
        action = "store_true"
    )
    parser.add_argument(
        "-v",
        help = "Enable verbosity",
        action = "store_true"
    )
    parser.add_argument("file")
    args = parser.parse_args()
    sb = Colibri(
        debug   = args.v,
        network = args.network,
        skip_sleep = not args.no_skip_sleep,
        output_file = args.output,
        rootfs  = args.rootfs,
    )
    print(cyan("[*] Running ") + yellow(args.file) + cyan(" with options:"))
    print("\t" + cyan("Rootfs: ") + args.rootfs)
    print("\t" + cyan("Network: ") + str(args.network))
    print("\t" + cyan("Timeout: ") + str(args.timeout) + "s")
    print("\t" + cyan("Output: ") + args.output)
    print()
    sb.run(
        fpath   = args.file,
        timeout = args.timeout,
    )

# Absolutely necessary
def print_banner():
    for root, dirs, files in os.walk(
        os.path.join(
            os.path.dirname(__file__),
            "banners"
        )
    ):
        with open(
            os.path.join(root, random.choice(files))
        ) as f:
            color = random.choice([blue, red, yellow, green, magenta, cyan])
            print(color(f.read()))