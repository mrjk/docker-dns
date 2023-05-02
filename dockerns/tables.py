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
    # WIPP
    return
    global QUIET
    if not QUIET:
        now = datetime.now().isoformat()
        line = "%s [%s] %s\n" % (now, PROCESS, msg % args)
        sys.stderr.write(line)
        sys.stderr.flush()


class TableInstance:
    "Single TableInstance"

    def __init__(self, name, conf=None):
        self._tables = {}
        self.name = name
        self.conf = conf or {}

        # V1
        # self.add = self._table.add
        # self.rename = self._table.rename
        # self.remove = self._table.remove

    # V2
    def add(self, name, address):
        for table_name, table in self._tables.items():
            table.add(name, address)

    def rename(self, old_name, new_name):
        for table_name, table in self._tables.items():
            table.add(old_name, new_name)

    def remove(self, name):
        for table_name, table in self._tables.items():
            table.add(name)

    def debug(self):
        ret = {
            "conf": self.__dict__,
            "_tables": {key: val for key, val in self._tables.items()},
            #'_tables': { key: val.debug() for key, val in self._tables.items() },
        }
        return ret


class TableInstances:
    "TableInstances"

    confs = {"default": {}}

    def __init__(self, confs=None):
        self.tables_conf = confs or dict(self.confs)
        self._tables = {
            name: TableInstance(name, conf) for name, conf in self.tables_conf.items()
        }

    def _filter_tables(self, tables):
        # TOFIX: Yield this please
        ret = {}
        for table_name in tables:
            table = self._tables.get(table_name, None)
            if not table:
                continue
            ret[table_name] = table
        return ret.items()

    def add(self, tables, name, address):
        for table_name, table in self._filter_tables(tables):
            table.add(name, address)

    def rename(self, tables, name, new_name):
        for table_name, table in self._filter_tables(tables):
            table.rename(name, new_name)

    def remove(self, tables, name):
        for table_name, table in self._filter_tables(tables):
            table.remove(name)

    def ensure(self, name):
        if name not in self._tables:
            self._tables[name] = TableInstance(name, {})
        return self._tables[name]

    def get_table(self, name):
        # print ("FETCHCCCC")
        # pprint (self._tables[name])
        return self._tables[name]._table

    def debug(self):
        print("Tables debug:")
        ret = {}
        for table_name, table in self._tables.items():
            ret[table_name] = table.debug()

        pprint(ret, indent=2)
        return ret
