from datetime import datetime
from smap.models import DNSList
from smap.models import ScanInstance
from smap.models import ScanResult
from urlparse import urlparse

import re
import getpass
import grequests
import settings
import sys
import time
import random

SUPPORTED = dict(http=80, https=443)


def add_port(protocol):
    """Return a port based on protocol."""
    return SUPPORTED.get(protocol, 80)


def add_host(host):
    """Return a UCF hostname."""
    return host if re.match(
        r'^(ucf\.edu|.*ucf\.edu)', host) else '{host}.ucf.edu'.format(host=host)


def url_factory(self):
    """Generate URLs to scan by a specified protocol."""
    def by_protocol(protocol, session):
        if protocol not in SUPPORTED.keys():
            print >> sys.stderr, 'ERROR: \'{invalid}\' is currently not supported. Try: {supported}.'.format(
                invalid=protocol, supported=SUPPORTED.keys())
            sys.exit(1)

        mappings = []
        for record in session.query(DNSList).all():
            domain_name = record.domain.name
            external_ip = record.firewall_map.external_ip.ip_address
            mappings.append(
                ('{host}'.format(
                    host=add_host(domain_name)),
                    '{protocol}://{ipaddr}:{port}'.format(
                    protocol=protocol,
                    ipaddr=str(external_ip),
                    port=add_port(protocol))))
        return mappings
    return by_protocol


def handle_errors(request, exception):
    """Error hook handler."""
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

    # todo: obtain session obj
    # session.add(scan_result)


def response_hook(response, *args, **kwargs):
    """Result hook handler."""
    url = urlparse(response.url)
    port = url.port
    protocol = url.scheme
    response_code = response.status_code

    scan_result = ScanResult(
        port=port,
        protocol=protocol,
        response_code=response_code,
        message=None)

    # todo: obtain session obj
    # session.add(scan_result)


def scan(session):
    """Start scan and record results."""
    start_time = datetime.now()
    author = getpass.getuser()
    http, https = SUPPORTED.keys()[0], SUPPORTED.keys()[1]
    url_factory = url_factory()
    urls = url_factory(http) + url_factory(https)

    async_requests = [
        grequests.head(
            url=url,
            allow_redirects=False,
            headers={
                'User-Agent': random.choice(settings.USER_AGENTS), 'Host': host},
            hooks=dict(response=response_hook),
            timeout=settings.TIMEOUT) for host, url in urls]
    grequests.map(
        requests=async_requests,
        size=settings.CONCURRENT_REQUESTS,
        exception_handler=handle_errors)

    end_time = datetime.now()
    scan_instance = ScanInstance(
        start_time=start_time,
        end_time=end_time,
        author=author)
    session.add(scan_instance)
