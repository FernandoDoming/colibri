import os
import json
import time
import random
import hashlib
import signal
import logging
import argparse
import shutil

from ctypes import c_bool
from multiprocessing import Manager, Value

from qiling import Qiling
from qiling.const import QL_INTERCEPT, QL_VERBOSE
from qiling.os.posix.const import NR_OPEN

from colibri.syscalls.network import *
from colibri.syscalls.filesystem import *
from colibri.syscalls.time import *
from colibri.syscalls.unistd import *
from colibri.syscalls.signal import *

from colibri.utils.cmdline import (
    blue, red, yellow, green, magenta, cyan,
)

from colibri.core.classes import dotdict, AtomicOpen
from colibri.core.postprocess import PostProcess
from colibri.core.const import *
from colibri.utils.cwd import get_sample_results_path

LOG_FORMAT = "%(asctime)-15s [%(levelname)s] - %(message)s"
logging.basicConfig(format=LOG_FORMAT)
log = logging.getLogger("colibri.main")
log.setLevel(logging.INFO)

# -----------------------------------------------------------------
class Colibri():
    replaced_syscall = {
        # System
        "fork": syscall_fork,
        "vfork": syscall_vfork,
        "prctl": syscall_prctl,
        "signal": syscall_signal,
        "kill": syscall_kill,
        # Time
        "nanosleep": syscall_nanosleep,
        "clock_nanosleep": syscall_clock_nanosleep,
        "clock_nanosleep_time64": syscall_clock_nanosleep_time64,
        # Network
        "socket": syscall_socket,
        "connect": syscall_connect,
        "send": syscall_send,
        "sendto": syscall_sendto,
        "recv": syscall_recv,
        "recvfrom": syscall_recvfrom,
        "accept": syscall_accept,
        "setsockopt": syscall_setsockopt,
        "getsockopt": syscall_getsockopt,
        "getsockname": syscall_getsockname,
        # Filesystem
        "write": syscall_write,
        "readlink": syscall_readlink,
        "unlink": syscall_unlink,
        "_newselect": syscall__newselect,
    }
    on_enter_hooks = {
        # exit does not return
        "exit": syscall_exit_onenter,
        "exit_group": syscall_exit_group_onenter,
        # execve does not return
        "execve": syscall_execve_onenter,
    }
    on_exit_hooks = {
        "open": syscall_open_onexit,
        "clone": syscall_clone_onexit,
        "close": syscall_close_onexit,
        "setsid": syscall_setsid_onexit,
        "rt_sigaction": syscall_rt_sigaction_onexit,
        # Network
        "bind": syscall_bind_onexit,
        "listen": syscall_listen_onexit,
    }

    # ---------------------------------------
    def __init__(self, **kwargs) -> None:
        self.smm = Manager()
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
        self.ql = Qiling(
            argv = [fpath] + self.options.args,
            rootfs = self.options.rootfs,
            env = self.options.env,
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

        # ql.run() returns when the original process exits
        # but malware may create detached childs that keep running
        # wait them until timeout if there are childs
        while self.running.value and self.get_running_pids():
            time.sleep(.2)

    # ---------------------------------------
    def handle_signal(self, signum, frame):
        if self.running.value:
            log.info("Colibri execution hit timeout. Stopping...")
            self.stop()

    def stop(self):
        self.running = Value(c_bool, False)
        p = PostProcess(
            for_file = self.analyzed_sample["path"],
        )
        p.run()
        p.save()
        if self.options.get("dump", False):
            p.dump_ram()

        pids = self.get_running_pids()
        log.info(
            "Stopping pids %s", ", ".join([str(x) for x in pids])
        )
        for pid in pids:
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
    def log_syscall(self, name, args = {}, retval = None, extra = {}):
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
    def get_running_pids(self) -> list:
        r_path = get_sample_results_path(self.analyzed_sample["sha256"])
        pidf = os.path.join(r_path, "pids.json")
        if not os.path.isfile(pidf):
            return []

        with AtomicOpen(pidf, "r") as f:
            d = f.read()
            if not d:
                return []
            return json.loads(d)

    def report_new_child(self, pid, ppid = None):
        try:
            if not ppid:
                ppid = os.getpid()

            pids = self.get_running_pids()
            r_path = get_sample_results_path(self.analyzed_sample["sha256"])
            pidf = os.path.join(r_path, "pids.json")
            with AtomicOpen(pidf, "w") as f:
                pids.append(pid)
                f.write(json.dumps(pids))

            log.info("New child reported. PID: %d, PPID: %d", pid, ppid)

        except Exception:
            log.exception(
                "Failed to report new child %d, PPID: %d",
                pid,
                ppid
            )

    def report_exit(self, status):
        try:
            pid = os.getpid()
            pids = self.get_running_pids()
            r_path = get_sample_results_path(self.analyzed_sample["sha256"])
            pidf = os.path.join(r_path, "pids.json")
            if pid in pids:
                pids.remove(pid)

            with AtomicOpen(pidf, "w") as f:
                f.write(json.dumps(pids))

            log.info("PID %d: Exited with status %d", pid, status)
        except Exception:
            log.exception("Failed to report exit %s", pid)

# -----------------------------------------------------------------
class __arg_env(argparse.Action):
    def __call__(self, parser, namespace, values, option_string):
        env = getattr(namespace, self.dest) or {}
        for envstring in values:
            split = envstring.split("=")
            if len(split) == 2:
                env[split[0]] = split[1]
        setattr(namespace, self.dest, env)

def main():
    parser = argparse.ArgumentParser()
    default_rootfs = os.path.join(os.path.expanduser("~"), ".colibri", "rootfs")
    parser.add_argument(
        "-fs", "--rootfs",
        help = "Root directory to use as filesystem (default: %s)" % default_rootfs,
        default = default_rootfs
    )
    parser.add_argument(
        "--args",
        default=[],
        metavar="ARGV",
        nargs="*",
        dest="args",
        help="Run arguments"
    )
    parser.add_argument(
        "--env",
        metavar="KEY=VALUE",
        action=__arg_env,
        nargs="*",
        default={},
        help="Environment variables"
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
        args = args.args,
        env = args.env,
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
        print("\t" + cyan("Args: ") + " ".join(args.args))
        print("\t" + cyan("Env: ") + str(args.env))
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