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

from lib.config import DockerNSConfig

DOCKERNS_CONFIG = os.environ.get('DOCKERNS_CONFIG_FILE', 'config.yml')
PROCESS = 'dockerdns'
DOCKER_SOCK = 'unix:///docker.sock'
DNS_BINDADDR = '0.0.0.0:53'
DNS_RESOLVER = ['8.8.8.8']
DNS_RESOLVER_TIMEOUT = 3.0
RE_VALIDNAME = re.compile('[^\w\d.-]')
QUIET = 0
EPILOG = '''

'''

network_blacklist = os.environ.get('NETWORK_BLACKLIST')
if not network_blacklist:
    network_blacklist = "255.255.255.255/32"

network_blacklist = network_blacklist.split()
for i, network in enumerate(network_blacklist):
    network_blacklist[i] = ip_network(network)



def log(msg, *args):
    # WIPP
    return
    global QUIET
    if not QUIET:
        now = datetime.now().isoformat()
        line = u'%s [%s] %s\n' % (now, PROCESS, msg % args)
        sys.stderr.write(line)
        sys.stderr.flush()


#def get(d, *keys):
#    empty = {}
#    return reduce(lambda d, k: d.get(k, empty), keys, d) or None



class NameTable():

    'Table mapping names to addresses'

    def __init__(self, records):
        self._storage = defaultdict(set)
        self._lock = threading.Lock()
        for rec in records:
            self.add(rec[0], rec[1])

    def debug(self):

        ret = {} #dict(self._storage)
        for k, v in self._storage.items():
            name = '.'.join([t.decode() for t in k])
            ret[name] = v

        return ret

    def add(self, name, addr):
        if name.startswith('.'):
            name = '*' + name
        key = self._key(name)
        if key:
            with self._lock:
                for network in network_blacklist:
                    if addr and ip_address(addr) in network:
                        log('skipping table.add %s -> %s (blacklisted network)', name, addr)
                        return
                log('table.add %s -> %s', name, addr)
                self._storage[key].add(addr)

                # reverse map for PTR records
                addr = '%s.in-addr.arpa' % '.'.join(reversed(addr.split('.')))
                key = self._key(addr)
                log('table.add %s -> %s', addr, name)
                self._storage[key].add(name)

    def get(self, name):
        key = self._key(name)
        if key:
            with self._lock:
                res = self._storage.get(key)

                wild = re.sub(r'^[^\.]+', '*', name)
                wildkey = self._key(wild)
                wildres = self._storage.get(wildkey)

                if res:
                    log('table.get %s with %s' % (name, ", ".join(addr for addr in res)))
                elif wildres:
                    log('table.get %s with %s' % (name, ", ".join(addr for addr in wildres)))
                    res = wildres
                else:
                    log('table.get %s with NoneType' % (name))
                return res

    def rename(self, old_name, new_name):
        if not old_name or not new_name:
            return
        old_name = old_name.lstrip('/')
        old_key = self._key(old_name)
        new_key = self._key(new_name)
        with self._lock:
            self._storage[new_key] = self._storage.pop(old_key)
            log('table.rename (%s -> %s)', old_name, new_name)

    def remove(self, name):
        key = self._key(name)
        if key:
            with self._lock:
                if key in self._storage:
                    log('table.remove %s', name)
                    del self._storage[key]

    def _key(self, name):
        try:
            label = DNSLabel(name.lower()).label
            return label
        except Exception:
            return None


class TableInstance():
    'Single TableInstance'

    def __init__(self, name, conf=None):

        self._table = NameTable([])
        self.name = name
        self.conf = conf or {}


        self.add = self._table.add
        self.rename = self._table.rename
        self.remove = self._table.remove

#    def add(self, name, address):
#        self._table.add(name, address)


    def debug(self):
        ret = {
                'conf': self.__dict__,
                'table': self._table.debug(),
                }
        return ret

class TableInstances():
    'TableInstances'

    confs = {
            'default': {}
            }

    def __init__(self, confs=None):

        self.tables_conf = confs or dict(self.confs)
        self._tables = { name: TableInstance(name, conf) for name, conf in self.tables_conf.items() }


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


    def get_table(self, name):
        #print ("FETCHCCCC")
        #pprint (self._tables[name])
        return self._tables[name]._table

    def debug(self):

        ret = {}
        for table_name, table in self._tables.items():
            ret[table_name] =  table.debug()

        pprint (ret)
        return ret


            






