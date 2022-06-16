import sys

def common_syscall_exit(ql):
    if not ql.hb.running.value:
        sys.exit(0)