import os
import json
import time
import random
import hashlib
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
from colibri.core.postprocess import PostProcess
from colibri.core.const import *
from colibri.utils.cwd import get_sample_results_path

LOG_FORMAT = "%(asctime)-15s [%(levelname)s] - %(message)s"
logging.basicConfig(format=LOG_FORMAT)
log = logging.getLogger("colibri.main")
log.setLevel(logging.INFO)

# -----------------------------------------------------------------
class Colibri(metaclass=Singleton):
    replaced_syscall = {
        # System
        "fork": syscall_fork,
        "vfork": syscall_vfork,
        # Time
        "nanosleep": syscall_nanosleep,
        "clock_nanosleep": syscall_clock_nanosleep,
        "clock_nanosleep_time64": syscall_clock_nanosleep_time64,
        # Network
        "connect": syscall_connect,
        "send": syscall_send,
        "recv": syscall_recv,
        "setsockopt": syscall_setsockopt,
        "getsockopt": syscall_getsockopt,
        "getsockname": syscall_getsockname,
        # Filesystem
        "write": syscall_write,
        "unlink": syscall_unlink,
        "_newselect": syscall__newselect,
    }
    on_enter_hooks = {
        # exit does not return
        "exit": syscall_exit_onenter,
        "exit_group": syscall_exit_group_onenter,
        # execve does not return
        "execve": syscall_execve_onenter,
        # Network
        "accept": syscall_accept_onenter,
    }
    on_exit_hooks = {
        "open": syscall_open_onexit,
        "readlink": syscall_readlink_onexit,
        "clone": syscall_clone_onexit,
        "close": syscall_close_onexit,
        # Network
        "bind": syscall_bind_onexit,
        "listen": syscall_listen_onexit,
    }

    # ---------------------------------------
    def __init__(self, **kwargs) -> None:
        self.smm = Manager()
        self.pids = self.smm.list()
        self.running = Value(c_bool, False)

        self.options = dotdict(**kwargs)

    # ---------------------------------------
    def set_hooks(self):
        for syscall_name, syscall_fn in self.replaced_syscall.items():
            self.ql.os.set_syscall(syscall_name, syscall_fn)

        for syscall_name, syscall_fn in self.on_enter_hooks.items():
            self.ql.os.set_syscall(syscall_name, syscall_fn, QL_INTERCEPT.ENTER)

        for syscall_name, syscall_fn in self.on_exit_hooks.items():
            self.ql.os.set_syscall(syscall_name, syscall_fn, QL_INTERCEPT.EXIT)

    # ---------------------------------------
    def run(self, fpath, timeout = 10):
        self.ql = qlapi.Qiling(
            [fpath],
            self.options.rootfs,
            multithread = True,
            verbose=QL_VERBOSE.DEBUG if self.options.get("debug", False) else QL_VERBOSE.OFF
        )
        self.ql.hb = self
        self.analyzed_sample = {
            "path": os.path.abspath(fpath),
            "sha256": hashlib.sha256(open(fpath, "rb").read()).hexdigest(),
        }
        self.set_hooks()
        self.reset_filesystem()
        self.create_results_dir()
        self.main_pid = os.getpid()

        # Doing this instead of Qiling's timeout because
        # Qiling's timeout does not stop forked children
        signal.signal(signal.SIGALRM, self.handle_signal)
        signal.alarm(timeout)
        try:
            self.running = Value(c_bool, True)
            self.analysis_start_time = time.time()
            self.ql.run()
        except Exception:
            log.exception("Failed to run Qiling on sample %s", fpath)
            self.stop()

        while self.running.value:
            time.sleep(1)

    # ---------------------------------------
    def handle_signal(self, signum, frame):
        self.stop()

    def stop(self):
        self.running = Value(c_bool, False)
        log.info("Colibri execution hit timeout. Stopping...")
        p = PostProcess(
            for_file = self.analyzed_sample["path"],
        )
        p.run()
        p.save()
        if self.options.get("dump", False):
            p.dump_ram()

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
        self.ql.emu_stop()

    # ---------------------------------------
    def create_results_dir(self):
        anal_path = get_sample_results_path(self.analyzed_sample["sha256"])
        if os.path.isdir(anal_path):
            shutil.rmtree(anal_path)
        os.makedirs(anal_path)
        with open(os.path.join(anal_path, "report.json"), "w") as f:
            f.write("{}")

    # ---------------------------------------
    def reset_filesystem(self):
        dirname    = os.path.dirname(__file__)
        rootfs_dir = os.path.join(dirname, "rootfs")
        log.info("Resetting filesystem to %s", rootfs_dir)
        if os.path.exists(self.options.rootfs):
            shutil.rmtree(self.options.rootfs)
        shutil.copytree(rootfs_dir, self.options.rootfs)

        # Copy sample to the rootfs so its available to the analysis
        sample_dir = os.path.dirname(self.analyzed_sample["path"])
        target_dir = os.path.join(self.options.rootfs, sample_dir[1:])
        os.makedirs(target_dir, exist_ok=True)
        shutil.copy(self.analyzed_sample["path"], target_dir)

    # ---------------------------------------
    def log_syscall(self, name, args = {}, retval = "None", extra = {}):
        caller_pid = os.getpid()
        if not self.running.value:
            log.info(
                "PID %d: Asked to log syscall %s but analysis has finished.",
                caller_pid,
                name
            )
            return

        try:
            # log.debug(
            #     "PID %d: %s(%s) = %s",
            #     caller_pid,
            #     name,
            #     ", ".join([f"{k} = {v}" for k, v in args.items()]),
            #     retval
            # )
            toff = time.time() - self.analysis_start_time
            r_path = get_sample_results_path(self.analyzed_sample["sha256"])
            with open(os.path.join(r_path, "syscalls.json"), "a") as f:
                syscall_data = {
                    "pid": caller_pid,
                    "name": name,
                    "time": toff,
                    "args": args,
                    "return": retval,
                    "extra": extra,
                }
                f.write(json.dumps(syscall_data) + "\n")

        except Exception:
            log.exception(
                "PID %d: Failed to log syscall %s",
                caller_pid,
                name
            )

    # ---------------------------------------
    def report_new_child(self, pid, ppid = None):
        try:
            if not ppid:
                ppid = os.getpid()

            log.info("New child reportd. PID: %d, PPID: %d", pid, ppid)
            self.pids.append(pid)

            # proctree = self.report[CATEGORY_PROCTREE]
            # if ppid not in proctree:
            #     proctree[ppid] = []
            # proctree[ppid].append(pid)
            # self.report[CATEGORY_PROCTREE] = proctree
        except Exception:
            log.exception(
                "Failed to report new child %d, PPID: %d",
                pid,
                ppid
            )

    def report_exit(self, status):
        try:
            pid = os.getpid()
            log.info("PID %d: Exited with status %d", pid, status)
            if pid in self.pids:
                self.pids.remove(pid)
        except Exception:
            log.exception("Failed to report exit %s", pid)

# -----------------------------------------------------------------
def main():
    import argparse
    parser = argparse.ArgumentParser()
    default_rootfs = os.path.join(os.path.expanduser("~"), ".colibri", "rootfs")
    parser.add_argument(
        "-fs", "--rootfs",
        help = "Root directory to use as filesystem (default: %s)" % default_rootfs,
        default = default_rootfs
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
        "-d", "--dump",
        help = "Enable memory dumps",
        action = "store_true"
    )
    parser.add_argument(
        "-v",
        help = "Enable verbosity",
        action = "store_true"
    )
    parser.add_argument(
        "-q",
        help = "Enable quiet mode",
        action = "store_true"
    )
    parser.add_argument("file")
    args = parser.parse_args()
    if args.q:
        log.setLevel(logging.ERROR)
    elif args.v:
        log.setLevel(logging.DEBUG)

    sb = Colibri(
        debug   = args.v,
        network = args.network,
        skip_sleep = not args.no_skip_sleep,
        rootfs = args.rootfs,
        dump = args.dump,
    )
    if not args.q:
        print_banner()
        print(cyan("[*] Running ") + yellow(args.file) + cyan(" with options:"))
        print("\t" + cyan("Rootfs: ") + args.rootfs)
        print("\t" + cyan("Network: ") + str(args.network))
        print("\t" + cyan("Timeout: ") + str(args.timeout) + "s")
        print("\t" + cyan("Dumps Enabled: ") + str(args.dump))
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