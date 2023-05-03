#!/usr/bin/env python


# dockerdns - simple, automatic, self-contained dns server for docker

# monkey patch everything
# ruff: noqa: E402
from gevent import monkey

monkey.patch_all()


# core
import os
import re
import sys
from urllib.parse import urlparse
import argparse
from types import SimpleNamespace
from pprint import pprint

# libs
import gevent
import urllib3

from dockerns.tables import StoreMgr
from dockerns.model import BackendMgr, SourceMgr
from dockerns.config import DockerNSConfig
from dockerns.common import log


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Import local libs


DOCKERNS_CONFIG = os.environ.get("DOCKERNS_CONFIG_FILE", "config.yml")
PROCESS = "dockerdns"
DOCKER_SOCK = "unix:///docker.sock"
DNS_BINDADDR = "0.0.0.0:53"
DNS_RESOLVER = ["8.8.8.8"]
DNS_RESOLVER_TIMEOUT = 3.0
RE_VALIDNAME = re.compile("[^\w\d.-]")
QUIET = 0
EPILOG = """

"""


def check(args):
    url = urlparse(args.docker)
    if url.scheme in ("unix", "unix+http"):
        # check if the socket file exists
        if not os.path.exists(url.path):
            log("unix socket %r does not exist", url.path)
            sys.exit(1)


def parse_args():
    docker_url = os.environ.get("DOCKER_HOST")
    if not docker_url:
        docker_url = DOCKER_SOCK
    parser = argparse.ArgumentParser(
        PROCESS, epilog=EPILOG, formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument(
        "--config", default=DOCKERNS_CONFIG, help="dockerns yaml configuration"
    )

    parser.add_argument(
        "--docker", default=docker_url, help="Url to docker TCP/UNIX socket"
    )
    parser.add_argument(
        "--dns-bind", default=DNS_BINDADDR, help="Bind address for DNS server"
    )
    parser.add_argument(
        "--domain", default="docker", help="Base domain name for registered services"
    )
    parser.add_argument(
        "--expose-ip",
        default="",
        help="Default IP to report on exposed services, skipped if empty",
    )
    parser.add_argument(
        "--resolver",
        default=DNS_RESOLVER,
        nargs="*",
        help="Servers for recursive DNS resolution",
    )
    parser.add_argument(
        "--no-recursion",
        action="store_const",
        const=1,
        help="Disables recursive DNS queries",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_const", const=1, help="Quiet mode"
    )
    parser.add_argument(
        "-r", "--record", nargs="*", default=[], help="Add a static record `name:host`"
    )
    return parser.parse_args()


class App:
    def __init__(self):
        _conf = DockerNSConfig()
        self.settings = SimpleNamespace(**_conf.get_conf("config", {}))

        pprint(self.settings)

        self.conf = _conf

    def cli(self):
        # global QUIET
        # QUIET = False

        # Create stores
        wait_list = []
        stores = StoreMgr(
            confs=self.conf.get_conf("tables", default={}), settings=self.settings
        )

        # Start backends
        backends = BackendMgr(
            self,
            stores,
            confs=self.conf.get_conf("outputs", default={}),
            settings=self.settings,
        )
        wait_list.extend(backends.start())

        # Start sources
        sources = SourceMgr(
            self,
            stores,
            confs=self.conf.get_conf("sources", default={}),
            settings=self.settings,
        )
        wait_list.extend(sources.start())

        # Wait for background processes
        log("Background processes: %s" % wait_list)
        gevent.wait(wait_list)


# def main2():
#
#     global QUIET
#     args = parse_args()
#     check(args)
#     if args.record:
#         args.record = map(splitrecord, args.record)
#
#     QUIET = args.quiet
#     resolver = () if args.no_recursion else args.resolver
#     table = NameTable([(k + "." + args.domain, v) for (k, v) in args.record])
#     tls_config = None
#     if args.docker.startswith('https://'):
#         tls_config = docker.tls.TLSConfig(verify=False)
#
#
#
#
#     log('DOCKER_HOST %s' % args.docker)
#     client = None
#     try:
#         client = docker.Client(args.docker, version='auto', tls=tls_config)
#     except docker.errors.TLSParameterError as e:
#         log('Docker error: %s' % e)
#         sys.exit(1)
#     monitor = DockerMonitor(client, table, args.domain, args.expose_ip)
#     dns = DnsServer(args.dns_bind, table, resolver)
#
#     gevent.signal_handler(signal.SIGINT, stop, dns)
#     gevent.signal_handler(signal.SIGTERM, stop, dns)
#     dns.start()
#     gevent.wait([gevent.spawn(monitor.run)])


def main():
    app = App()
    app.cli()


if __name__ == "__main__":
    main()
