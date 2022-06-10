import sys

# -----------------------------------------------------------------
def write_onenter(ql, fd, buf, count):
    try:
        data = ql.mem.read(buf, count)
        filename = ql.os.fd[fd].name

        fs = ql.hb.report["filesystem"]
        if not "write" in fs:
            fs["write"] = {}
        if not filename in fs["write"]:
            fs["write"][filename] = ""
        fs["write"][filename] += data.decode("utf-8")
        ql.hb.report["filesystem"] = fs
    except Exception:
        ql.log.info(sys.exc_info()[0])

# -----------------------------------------------------------------