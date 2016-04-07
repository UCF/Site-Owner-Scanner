try:
    from ipaddress import ip_address
except ImportError:
    from ipaddr import IPAddress as ip_address

from models import DNSList
from models import ScanInstance
from models import ScanResult
from time import strftime
from urlparse import urlparse

import re
import getpass
import grequests
import settings
import sys
import time
import random


class Scanner(object):

    supported = dict(http=80, https=443)

    def __init__(self):
        self.session = None

    @staticmethod
    def __add_host(host):
        return host if re.match(
            r'^(ucf\.edu|.*ucf\.edu)', host) else '{host}.ucf.edu'.format(host=host)

    @staticmethod
    def __add_port(protocol):
        return Scanner.supported.get(protocol, 80)

    def __url_factory(self):
        def by_protocol(protocol, session):
            if protocol not in self.supported:
                print >> sys.stderr, 'ERROR: \'{protocol}\' is not supported.'.format(
                    protocol=protocol)
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
        url = urlparse(response.url)
        port = url.port
        protocol = url.scheme
        response_code = response.status_code
        ipv4_addr = re.search(r'(\d{1,3}\.){3}\d{1,3}', response.url).group(0)

        ip = IP(ip_address=ipv4_addr)
        # We'll need to tie back a domain by this specific IP address

        scan_result = ScanResult(
            port=port,
            protocol=protocol,
            response_code=response_code,
            message=None,
            ip=ip,
            domain=domain)
        self.session.add(scan_result)
        print '{url} is alive on port {port}'.format(strftime(url=response.url, port=port)

    def __failure_hook(self, request, exception):
        url = urlparse(request.url)
        port = url.port
        protocol = url.scheme
        response_code = None
        message = request.exception.message
        ipv4_addr = re.search(r'(\d{1,3}\.){3}\d{1,3}', request.url).group(0)

        ip = IP(ip_address=ipv4_addr)
        # Same as above ...

        scan_result=ScanResult(
            port=port,
            protocol=protocol,
            response_code=response_code,
            message=message,
            ip=ip,
            domain=domain)
        self.session.add(scan_result)

    def scan(self, session):
        start_time = strftime('%Y-%m-%d %H:%M:%S')
        self.session = session
        author = getpass.getuser()
        http, https = self.supported.keys()[0], self.supported.keys()[1]
        url_factory = self.__url_factory()
        urls = url_factory(http, session) + url_factory(https, session)

        async_requests=[
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

        end_time=strftime('%Y-%m-%d %H:%M:%S')
        scan_instance=ScanInstance(
            start_time=start_time,
            end_time=end_time,
            author=author)
