import sys
import re
from functools import reduce
from datetime import datetime

QUIET=False
PROCESS = "dockerdns"

def log(msg, *args):
    global QUIET
    if not QUIET:
        now = datetime.now().isoformat()
        line = "%s [%s] %s\n" % (now, PROCESS, msg % args)
        sys.stderr.write(line)
        sys.stderr.flush()


def get(d, *keys):
    empty = {}
    return reduce(lambda d, k: d.get(k, empty), keys, d) or None


def splitrecord(rec):
    m = re.match(
        "([a-zA-Z0-9_-]*|\*):((?:[12]?[0-9]{1,2}\.){3}(?:[12]?[0-9]{1,2}){1}$)", rec
    )
    if not m:
        log("--record has invalid format, expects: `--record <host>:<ip>`")
        sys.exit(1)
    else:
        return (m.group(1), m.group(2))


def contains(txt, *subs):
    return any(s in txt for s in subs)

