from datetime import datetime
from models import DNSList
from models import ScanInstance
from models import ScanResult
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
        return supported.get(protocol, 80)

    def __url_factory(self):
        def by_protocol(protocol, session):
            if protocol not in supported:
                print >> sys.stderr, 'ERROR: \'{protocol}\' is not supported.'.format(
                    protocol=protocol)
                sys.exit(1)
            mappings = []
            for record in session.query(DNSList).all():
                domain_name = record.domain.name
                external_ip = record.firewall_map.external_ip.ip_address
                mappings.append(
                    ('{host}'.format(
                        host=__add_host(domain_name)),
                        '{protocol}://{ipaddr}:{port}'.format(
                        protocol=protocol,
                        ipaddr=str(external_ip),
                        port=__add_port(protocol))))
            return mappings
        return by_protocol

    def __success_hook(self, response, **kwargs):
        url = urlparse(response.url)
        port = url.port
        protocol = url.scheme
        response_code = response.status_code
        scan_result = ScanResult(
            port=port,
            protocol=protocol,
            response_code=response_code,
            message=None)
        self.session.add(scan_result)

    def __failure_hook(self, request, exception):
        url = urlparse(request.url)
        port = url.port
        protocol = url.scheme
        response_code = None
        message = request.exception.message
        scan_result = ScanResult(
            port=port,
            protocol=protocol,
            response_code=response_code,
            message=message)
        self.session.add(scan_result)

    def scan(self, session):
        start_time = datetime.now()
        self.session = session
        author = getpass.getuser()
        http, https = self.supported.keys()[0], self.supported.keys()[1]
        url_factory = self.__url_factory()
        scan_urls = url_factory(http) + url_factory(https)

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

        end_time = datetime.now()
        scan_instance = ScanInstance(
            start_time=start_time,
            end_time=end_time,
            author=author)
