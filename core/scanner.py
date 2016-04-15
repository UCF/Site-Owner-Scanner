from __future__ import print_function

from models import Domain
from models import DNSList
from models import IP
from models import ScanInstance
from models import ScanResult

from time import strftime
from urlparse import urlparse
from utils import ip2int
from utils import is_ipv4

import getpass
import grequests
import random
import re
import settings
import sys
import time
import sqlalchemy


class Scanner(object):

    """IP Scanner."""

    supported = dict(http=80, https=443)

    def __init__(self):
        self.session = None

    @staticmethod
    def __add_host(host):
        """Append a domain with 'ucf.edu'."""
        regexp = r'^(ucf\.edu|.*ucf\.edu)'
        return host if re.match(regexp, host) else '{0}.ucf.edu'.format(host)

    @staticmethod
    def __add_port(protocol):
        """Return a port based on the protocol."""
        return Scanner.supported.get(protocol)

    def __url_factory(self):
        """Closure factory to generate URLs (HTTP, HTTPS)."""
        def by_protocol(protocol, session):
            if protocol not in self.supported:
                print(
                    'ERROR: \'{0}\' is not supported.'.format(protocol),
                    file=sys.stderr)
                sys.exit(1)
            mappings = []
            for record in session.query(DNSList).all():
                domain_name = record.domain.name
                external_ip = record.firewall_map.external_ip.ip_address
                mappings.append(
                    ('{host}'.format(
                        host=self.__add_host(domain_name)),
                        '{protocol}://{ipaddr}:{port}'.format(
                        protocol=protocol,
                        ipaddr=str(external_ip),
                        port=self.__add_port(protocol))))
            return mappings
        return by_protocol

    def __success_hook(self, response, **kwargs):
        """Callback that occurs on response during an asynchronous request."""
        url = urlparse(response.url)
        port = url.port
        protocol = url.scheme
        response_code = response.status_code

        domain_name = response.request.headers['Host']
        ipaddr = re.search(r'(\d{1,3}\.){3}\d{1,3}', response.url).group(0)

        ip = IP(ip_address=ipaddr)
        domain = Domain(name=domain_name)

        scan_result = ScanResult(
            port=port,
            protocol=protocol,
            response_code=response_code,
            message=None,
            ip=ip,
            domain=domain)

        self.session.add(scan_result)
        print(' |- <{0}> {1} is alive on port {2} with IP {3}'.format(
            response_code, domain.name, port, ipaddr))

    def __find_owner(self, ip):
        """Determines site owner by comparing IP addresses as integers."""
        for record in self.session.query(IPRange).all():
            if not is_ipv4(record.start_ip) or not is_ipv4(record.end_ip):
                print('ERROR: invalid IP address.', file=sys.stderr)
                sys.exit(1)

                low, high = ip2int(record.start_ip), ip2int(record.end_ip)
                if ip2int(ip) >= low and ip2int(ip) <= high:
                    return record.dept

    def __failure_hook(self, request, exception):
        """Callback when an exception occurs in an asynchronous request."""
        url = urlparse(request.url)
        port = url.port
        protocol = url.scheme
        response_code = None
        message = request.exception.message

        domain_name = request.headers['Host']
        ipaddr = re.search(r'(\d{1,3}\.){3}\d{1,3}', request.url).group(0)

        ip = IP(ip_address=ipaddr)
        domain = Domain(name=domain_name)

        scan_result = ScanResult(
            port=port,
            protocol=protocol,
            response_code=response_code,
            message=message,
            ip=ip,
            domain=domain)

        self.session.add(scan_result)

        owner = self.__find_owner(ipaddr)
        print(' |- {0} is unreachable on port {1} with {2}, contact: {3}'.format(
            domain, port, ipaddr, owner))

    def scan(self, session):
        """Main scan entry point."""
        start_time = strftime('%Y-%m-%d %H:%M:%S')
        self.session = session
        author = getpass.getuser()
        http, https = self.supported.keys()[0], self.supported.keys()[1]
        url_factory = self.__url_factory()
        urls = url_factory(http, session) + url_factory(https, session)

        async_requests = [
            grequests.head(
                url=url,
                allow_redirects=False,
                headers={
                    'User-Agent': random.choice(settings.USER_AGENTS), 'Host': host},
                hooks=dict(response=self.__success_hook),
                timeout=settings.TIMEOUT) for host, url in urls]
        grequests.map(
            requests=async_requests,
            size=settings.CONCURRENT_REQUESTS,
            exception_handler=self.__failure_hook)

        end_time = strftime('%Y-%m-%d %H:%M:%S')
        scan_instance = ScanInstance(
            start_time=start_time,
            end_time=end_time,
            author=author)

        self.session.add(scan_instance)
