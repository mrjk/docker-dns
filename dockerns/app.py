#!/usr/bin/env python


# dockerdns - simple, automatic, self-contained dns server for docker

# monkey patch everything
from gevent import monkey

monkey.patch_all()

# python 3 compatibility
from functools import reduce
from builtins import map, str
from types import SimpleNamespace

# core
import argparse
from collections import defaultdict
from collections import namedtuple
from datetime import datetime
import json
import os
import re
import signal
import sys
import time
from urllib.parse import urlparse

from pprint import pprint

# libs
from dnslib import A, DNSHeader, DNSLabel, DNSRecord, PTR, QTYPE, RR
import docker
import gevent
from gevent import socket, threading
from gevent.server import DatagramServer
from gevent.resolver.ares import Resolver
from ipaddress import ip_network, ip_address

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Import local libs

from dockerns.config import DockerNSConfig

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


def log(msg, *args):
    global QUIET
    if not QUIET:
        now = datetime.now().isoformat()
        line = "%s [%s] %s\n" % (now, PROCESS, msg % args)
        sys.stderr.write(line)
        sys.stderr.flush()


def get(d, *keys):
    empty = {}
    return reduce(lambda d, k: d.get(k, empty), keys, d) or None


def splitrecord(rec):
    m = re.match(
        "([a-zA-Z0-9_-]*|\*):((?:[12]?[0-9]{1,2}\.){3}(?:[12]?[0-9]{1,2}){1}$)", rec
    )
    if not m:
        log("--record has invalid format, expects: `--record <host>:<ip>`")
        sys.exit(1)
    else:
        return (m.group(1), m.group(2))


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
        help="Default IP to report when service expose port on all IPs, skipped if empty",
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


import importlib
from dockerns.tables import TableInstances


def main():
    tmp = DockerNSConfig()

    tables = TableInstances(confs=tmp.get_conf("tables"))
    wait_list = []

    # Start outputs
    for output_name, output in tmp.get_conf("outputs").items():
        driver = output.get("driver", None)
        log("Loading output driver: %s" % driver)
        if not driver:
            continue
        pkg_name = f"dockerns.output.{driver}"
        mod = importlib.import_module(pkg_name)
        output = mod.Output(tables, conf=output)

        output.start_svc()

    # Start sources
    for src_name, src in tmp.get_conf("sources").items():
        driver = src.get("driver", None)
        if not driver:
            continue
        log("Loading source driver: %s" % driver)
        pkg_name = f"dockerns.source.{driver}"
        mod = importlib.import_module(pkg_name)
        src = mod.Source(tables, conf=src)

        wait_list.append(gevent.spawn(src.monitor.start))

    tables.debug()

    gevent.wait(wait_list)
    return


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

if __name__ == "__main__":
    main()
