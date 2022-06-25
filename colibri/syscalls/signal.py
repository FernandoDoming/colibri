import os
from qiling import Qiling

# -----------------------------------------------------------------
def syscall_kill(ql: Qiling, pid: int, sig: int):
    retval = 0

    os.kill(pid, sig)
    ql.hb.log_syscall(
        name = "kill",
        args = {
            "pid": pid,
            "sig": sig
        },
        retval = retval
    )
    return retval

# -----------------------------------------------------------------
def syscall_signal(ql: Qiling, sig: int, sighandler: int):
    retval = 0

    ql.hb.log_syscall(
        name = "signal",
        args = {
            "signal": sig,
            "handler": sighandler
        },
        retval = retval
    )

    return retval

# -----------------------------------------------------------------
def syscall_rt_sigaction_onexit(ql: Qiling, signum: int, act: int, oldact: int, retval: int):

    # pc = ql.arch.regs.arch_pc
    # print(f"PC: {pc}")
    # buf = ql.mem.read(pc, 50)
    # for insn in ql.arch.disassembler.disasm(buf, pc):
    #     print(f':: {insn.address:#x} : {insn.mnemonic:24s} {insn.op_str}')

    extra = {}
    if oldact:
        arr = ql.os.sigaction_act[signum] or [0] * 5
        data = b''.join(ql.pack32(key) for key in arr)
        extra["oldact"] = {}
        extra["oldact"]["arr"] = arr
        extra["oldact"]["data"] = data.hex()

    if act:
        extra["act"] = {}
        arr = [ql.mem.read_ptr(act + 4 * i, 4) for i in range(5)]
        extra["act"]["arr"] = arr

    ql.hb.log_syscall(
        name = "rt_sigaction",
        args = {
            "signum": signum,
            "act": act,
            "oldact": oldact
        },
        extra = extra,
        retval = retval
    )
