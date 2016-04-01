from smap.db import Domain
from smap.db import DNSList
from smap.db import DNSRecordType
from smap.db import FirewallMap
from smap.db import IP
from smap.db import IPRange

import csv
import re
import sys

RECORD_TYPES = ('A', 'AAAA')


def is_ipv4(record):
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', record):
        return False
    octets = [int(i) for i in re.findall(r'\d', record)]
    return all(octet >= 0 and octet <= 255 for octet in octets)


def parse_dns_records(target, session):
    with open(target, 'rb') as f:
        external = csv.reader(f, delimiter=',', quoting=csv.QUOTE_MINIMAL)
        external.next()
        for record in external:
            if record[1] in RECORD_TYPES:
                external_ip = IP(ip_address=' '.join(record[2].split()))
                if not is_ipv4(record[3]):
                    internal_ip = IP(ip_address=None)
                else:
                    internal_ip = IP(ip_address=' '.join(record[3].split()))
                firewall_map = FirewallMap(
                    internal_ip=internal_ip,
                    external_ip=external_ip)
                domain = Domain(name=' '.join(record[0].split()))
                record_type = DNSRecordType(name=' '.join(record[1].split()))
                dns_list = DNSList(
                    domain=domain,
                    record_type=record_type,
                    firewall_map=firewall_map)
                session.add_all([external_ip, internal_ip,
                                 firewall_map, domain, record_type, dns_list])


def parse_domain_info(target, session):
    with open(target, 'rb') as f:
        owners = csv.reader(f, delimiter=',', quoting=csv.QUOTE_MINIMAL)
        owners.next()
        for record in owners:
            if record[4] != 'All Off Campus Addresses':
                ip_range = IPRange(
                    start_ip=' '.join(record[2].split()),
                    end_ip=' '.join(record[3].split()),
                    desc=' '.join(record[4].split()),
                    dept=' '.join(record[5].split()))
                session.add(ip_range)
