from functools import reduce

import re


def is_ipv4(ip):
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
        return False
    octets = [int(i) for i in re.findall(r'\d', ip)]
    return all(octet >= 0 and octet <= 255 for octet in octets)


def ip2_int(ip):
    return reduce(lambda x, y: x << 8 | y, map(int, ip.split('.')))
