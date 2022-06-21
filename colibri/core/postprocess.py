import os
import json
import hashlib

from colibri.core.const import *
from colibri.core.classes import dotdict
from colibri.utils.cwd import get_sample_results_path

class PostProcess:
    def __init__(self, for_file, **kwargs):
        self.static_info = {
            "path": for_file,
            "sha256": hashlib.sha256(open(for_file, "rb").read()).hexdigest(),
        }
        self.options = dotdict(**kwargs)
        self.report = dict()

    # ---------------------------------------
    def run(self):
        self.report[CATEGORY_STATIC] = self.static_info
        self.report.setdefault(CATEGORY_SYSCALLS, {})
        self.report[CATEGORY_SYSCALLS] = self.parse_syscalls()
        self.report[CATEGORY_PROCTREE] = self.build_proctree()
        self.report[CATEGORY_NETWORK]  = self.extract_netinfo()

    def save(self):
        r_path = get_sample_results_path(self.static_info["sha256"])
        with open(os.path.join(r_path, "report.json"), "w") as f:
            f.write(
                json.dumps(self.report)
            )

    def dump_ram(self):
        r_path = get_sample_results_path(self.static_info["sha256"])
        dumps_path = os.path.join(r_path, "dump")
        os.makedirs(dumps_path)
        for i, mem_info_tuple in enumerate(self.ql.mem.save().get("ram", [])):
            lbound, ubound, perm, label, data = mem_info_tuple
            if not label.startswith("["):
                f = open(os.path.join(dumps_path, f"{label}_{i}"), "wb")
                f.write(data)
                f.close()

    # ---------------------------------------
    def get_report_path(self):
        return os.path.join(
            get_sample_results_path(self.static_info["sha256"]), "report.json"
        )

    # ---------------------------------------
    def parse_syscalls(self):
        syscalls_info = {}
        r_path = get_sample_results_path(self.static_info["sha256"])
        with open(os.path.join(r_path, "syscalls.json"), "r") as f:
            for line in f:
                syscall = json.loads(line)
                pid = syscall.pop("pid", 0)
                syscalls_info.setdefault(pid, [])
                syscalls_info[pid].append(syscall)
        return syscalls_info

    # ---------------------------------------
    def build_proctree(self):
        proctree = {}
        for pid, syscalls in self.report[CATEGORY_SYSCALLS].items():
            if pid not in proctree:
                proctree[pid] = {
                    "tstart": syscalls[0]["time"],
                    "tend": syscalls[-1]["time"],
                    "children": [],
                }
            for syscall in syscalls:
                sname = syscall["name"]
                if sname == "fork" or sname == "vfork" or sname == "clone":
                    proctree[pid]["children"].append(syscall["return"])
        return proctree

    # ---------------------------------------
    def extract_netinfo(self):
        netinfo = {
            "contacted_hosts": [],
            "sent_data": {}
        }
        for pid, syscalls in self.report[CATEGORY_SYSCALLS].items():
            for syscall in syscalls:
                sname = syscall["name"]
                if sname == "connect":
                    netinfo["contacted_hosts"].append(syscall["extra"])

                elif sname == "send" or (
                        sname == "write" and
                        syscall["args"]["filename"].startswith("socket(")
                ):
                    ip = syscall["extra"]["ip"]
                    port = syscall["extra"]["port"]
                    _type = syscall["extra"]["type"]
                    key = f"{ip}:{port}/{_type}"
                    netinfo["sent_data"].setdefault(key, [])
                    netinfo["sent_data"][key] = syscall["extra"]["data"]
        return netinfo