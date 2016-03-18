import csv
import re
import grequests
import settings
import sys
import random

from urlparse import urlparse


def is_reachable(response, **kwargs):
    url, port = response.url, urlparse(response.url).port
    if response.status_code != 200:
        print >> sys.stderr, 'bad response <{code}> for {url}'.format(
            code=response.status_code, url=url)
        return
    print 'port {port} is reachable for {url}'.format(port=port, url=url)


def handle_errors(request, exception):
    print 'request failed {url} => {error}'.format(url=request.url, error=exception.message)


class Scanner(object):

    def __init__(self, csv_path):
        self.csv_path = csv_path

    @staticmethod
    def add_host(host):
        return host if re.match(
            r'^(ucf\.edu|.*ucf\.edu)', host) else '{host}.ucf.edu'.format(host=host)

    @staticmethod
    def add_port(protocol):
        return 80 if protocol == settings.PROTOCOLS[0] else 443

    def url_factory(self):
        def by_protocol(protocol):
            if protocol not in settings.PROTOCOLS:
                raise ValueError(
                    '[!] \'{0}\' is not supported. Did you mean https?'.format(protocol))

            with open(self.csv_path, 'rb') as f:
                dns_dump = csv.reader(
                    f, delimiter=',', quoting=csv.QUOTE_MINIMAL)
                dns_dump.next()
                return [('{host}'.format(host=self.add_host(record[0])), '{protocol}://{ipaddr}:{port}'.format(
                    protocol=protocol, ipaddr=record[2], port=self.add_port(protocol))) for record in dns_dump]
        return by_protocol

    def scan(self):
        factory = self.url_factory()
        urls = factory(settings.PROTOCOLS[0]) + factory(settings.PROTOCOLS[1])
        user_agent = random.choice(settings.USER_AGENTS)

        async_requests = [
            grequests.head(
                url=url,
                allow_redirects=True,
                headers={'User-Agent': user_agent, 'Host': host},
                hooks={'response': is_reachable},
                timeout=settings.TIMEOUT
            ) for host, url in urls]
        grequests.map(
            requests=async_requests,
            size=settings.CONCURRENT_REQUESTS,
            exception_handler=handle_errors)
