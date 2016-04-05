from models import Domain
from models import DNSList
from models import DNSRecordType
from models import FirewallMap
from models import IP
from models import IPRange

import csv
import re
import sys


class Parser(object):

    record_types = ('A', 'AAAA')

    def __init__(self):
        self.session = None

    @staticmethod
    def __is_ipv4(record):
        if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', record):
            return False
        octets = [int(i) for i in re.findall(r'\d', record)]
        return all(octet >= 0 and octet <= 255 for octet in octets)

    def parse_dns_records(self, target, session):
        with open(target, 'rb') as f:
            self.session = session
            external = csv.reader(f, delimiter=',', quoting=csv.QUOTE_MINIMAL)
            external.next()
            for record in external:
                # Filter DNS record types by IPv4 or IPv6 address spaces (A, AAAA)
                # As of now, we only really need to check for valid IPv4
                # addresses
                if record[1] in self.record_types:
                    external_ip = IP(ip_address=' '.join(record[2].split()))
                    if not self.__is_ipv4(record[3]):
                        internal_ip = IP(ip_address=None)
                    else:
                        internal_ip = IP(
                            ip_address=' '.join(
                                record[3].split()))
                    firewall_map = FirewallMap(
                        internal_ip=internal_ip,
                        external_ip=external_ip)
                    domain = Domain(name=' '.join(record[0].split()))
                    record_type = DNSRecordType(
                        name=' '.join(record[1].split()))
                    dns_list = DNSList(
                        domain=domain,
                        record_type=record_type,
                        firewall_map=firewall_map)
                    self.session.add_all([external_ip, internal_ip,
                                          firewall_map, domain, record_type, dns_list])

    def parse_domain_info(self, target, session):
        with open(target, 'rb') as f:
            self.session = session
            owners = csv.reader(f, delimiter=',', quoting=csv.QUOTE_MINIMAL)
            owners.next()
            for record in owners:
                if not re.match(r'^All Off Campus Addresses',
                                record[4], re.IGNORECASE):
                    ip_range = IPRange(
                        start_ip=' '.join(record[2].split()),
                        end_ip=' '.join(record[3].split()),
                        description=' '.join(record[4].split()),
                        dept=' '.join(record[5].split()))
                    self.session.add(ip_range)
