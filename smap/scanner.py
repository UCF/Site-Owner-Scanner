from urlparse import urlparse

import csv
import re
import grequests
import settings
import sys
import random


def on_success(response, **kwargs):
    url, port = response.url, urlparse(response.url).port
    if response.status_code != 200:
        print >> sys.stderr, '<{code}> response for {url}'.format(
            code=response.status_code, url=url)
        return
    print 'port {port} is reachable for {url}'.format(port=port, url=url)


def handle_errors(request, exception):
    print 'ERROR: request failed {url} => {error}'.format(url=request.url, error=exception.message)


class Scanner(object):

    PROTOCOLS = ('http', 'https')

    def __init__(self, path):
        self.path = path

    @staticmethod
    def _add_host(host):
        return host if re.match(
            r'^(ucf\.edu|.*ucf\.edu)', host) else '{host}.ucf.edu'.format(host=host)

    @staticmethod
    def _add_port(protocol):
        return 80 if protocol == Scanner.PROTOCOLS[0] else 443

    def url_factory(self):
        def by_protocol(protocol):
            if protocol not in self.PROTOCOLS:
                print >> sys.stderr, 'ERROR: \'{given}\' is not supported. Try: {supported}'.format(
                    given=protocol, supported=self.PROTOCOLS)
                sys.exit(1)

            with open(self.path, 'rb') as dump:
                dns_dump = csv.reader(
                    dump, delimiter=',', quoting=csv.QUOTE_MINIMAL)
                dns_dump.next()

                whitelist = ('A', 'AAAA')
                return [('{host}'.format(host=self._add_host(record[0])), '{protocol}://{ipaddr}:{port}'.format(
                    protocol=protocol, ipaddr=record[2], port=self._add_port(protocol))) for record in dns_dump if record[1] in whitelist]
        return by_protocol

    def scan(self):
        url_factory = self.url_factory()
        urls = url_factory(self.PROTOCOLS[0]) + url_factory(self.PROTOCOLS[1])
        user_agent = random.choice(settings.USER_AGENTS)

        async_requests = [
            grequests.head(
                url=url,
                allow_redirects=False,
                headers={'User-Agent': user_agent, 'Host': host},
                hooks={'response': on_success},
                timeout=settings.TIMEOUT
            ) for host, url in urls]
        grequests.map(
            requests=async_requests,
            size=settings.CONCURRENT_REQUESTS,
            exception_handler=handle_errors)
