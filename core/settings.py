from __future__ import print_function
import sys

VERSION = '1.0'
PROGRAM = 'smap'
USER_AGENT = '{program}/{version}'.format(program=PROGRAM, version=VERSION)

TIMEOUT = 10
MAX_BYTES = 200000
CONCURRENT_REQUESTS = 20

try:
    from settings_local import *
except ImportError:
    print(
        "ERROR: local settings not found. Was 'settings_local.py' created?",
        file=sys.stderr)
    sys.exit(1)
