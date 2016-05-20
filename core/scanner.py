from __future__ import print_function

from models import Domain
from models import DNSList
from models import IP
from models import IPRange
from models import ScanInstance
from models import ScanResult

from output import display_failure
from output import display_results

from urlparse import urlparse
from utilities import ip2int
from utilities import is_ipv4

import getpass
import grequests
import re
import settings
import sys
import time
import sqlalchemy


class Scanner(object):

    supported = dict(http=80, https=443)

    def __init__(self):
        self.session = None

    @staticmethod
    def _add_host(host):
        ucf_host = r'^(ucf\.edu|.*ucf\.edu)$'
        if re.match(ucf_host, host) != None:
            return host
        return '{0}.ucf.edu'.format(host)

    @staticmethod
    def _add_port(protocol):
        return Scanner.supported.get(protocol)

    def url_factory(self):
        def by_protocol(protocol, session):
            if protocol not in self.supported:
                display_failure(
                    "'{0}' is not supported.".format(protocol))
                sys.exit(1)

            mappings = []
            for record in session.query(DNSList).all():
                domain_name = record.domain.name
                external_ip = record.firewall_map.external_ip.ip_address
                mappings.append(
                    ('{host}'.format(
                        host=self._add_host(domain_name)),
                        '{protocol}://{ipaddr}:{port}'.format(
                        protocol=protocol,
                        ipaddr=str(external_ip),
                        port=self._add_port(protocol))))
            return mappings
        return by_protocol

    def success_hook(self, response, **kwargs):
        url = urlparse(response.url)
        host = response.request.headers['Host']
        ip_address = re.search(r'(\d{1,3}\.){3}\d{1,3}', response.url).group(0)

        domain = Domain(name=host)
        ip = IP(ip_address=ip_address)

        scan_result = ScanResult(
            port=url.port,
            protocol=url.scheme,
            response_code=response.status_code,
            owner='',
            message=None,
            ip=ip,
            domain=domain)

        self.session.add(scan_result)

        display_results(
            ' |- domain: {domain} ip: {ip} port: {port} owner: {owner}'.format(
                domain=domain.name,
                ip=ip_address,
                port=url.port,
                owner=owner))

    def failure_hook(self, request, exception):
        url = urlparse(request.url)
        host = exception.request.headers['Host']
        ip_address = re.search(r'(\d{1,3}\.){3}\d{1,3}', request.url).group(0)

        domain = Domain(name=host)
        ip = IP(ip_address=ip_address)

        scan_result = ScanResult(
            port=url.port,
            protocol=url.scheme,
            response_code=None,
            owner='',
            message=request.exception.message,
            ip=ip,
            domain=domain)

        self.session.add(scan_result)

        display_results(
            ' |- domain: {domain} ip: {ip} port: {port} owner: {owner}'.format(
                domain=domain.name,
                ip=ip_address,
                port=url.port,
                owner=owner),
            contains_errors=True)

    def scan(self, session):
        time_started = time.strftime('%Y-%m-%d %H:%M:%S')
        author = getpass.getuser()
        http, https = self.supported.keys()[0], self.supported.keys()[1]
        url_factory = self.url_factory()
        urls = url_factory(http, session) + url_factory(https, session)

        self.session = session

        async_requests = [
            grequests.head(
                url=url,
                allow_redirects=False,
                headers={
                    'User-Agent': settings.USER_AGENT, 'Host': host},
                hooks=dict(response=self.success_hook),
                timeout=settings.TIMEOUT) for host, url in urls]

        grequests.map(
            requests=async_requests,
            size=settings.CONCURRENT_REQUESTS,
            exception_handler=self.failure_hook)

        time_ended = time.strftime('%Y-%m-%d %H:%M:%S')
        scan_instance = ScanInstance(
            start_time=time_started,
            end_time=time_ended,
            author=author)

        self.session.add(scan_instance)
