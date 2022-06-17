from qiling import Qiling

def read_str_array(ql: Qiling, addr: int):
    if addr:
        while True:
            elem = ql.mem.read_ptr(addr)

            if elem == 0:
                break

            yield ql.os.utils.read_cstring(elem)
            addr += ql.arch.pointersize