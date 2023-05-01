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


def log(msg, *args):
    global QUIET
    if not QUIET:
        now = datetime.now().isoformat()
        line = u'%s [%s] %s\n' % (now, PROCESS, msg % args)
        sys.stderr.write(line)
        sys.stderr.flush()

def get(d, *keys):
    empty = {}
    return reduce(lambda d, k: d.get(k, empty), keys, d) or None


def contains(txt, *subs):
    return any(s in txt for s in subs)

def stop(*servers):
    for svr in servers:
        if svr.started:
            svr.stop()
    sys.exit(signal.SIGINT)

class Output():
    'Store records in embedded DNS server'

    default_conf = {
                'bind': '127.0.0.1:53',
                #'resolvers': '8.8.8.8,8.8.4.4',
                'resolvers': '8.8.8.8',
                'recurse': True,
                'records': ['default'],
                'table': 'default',
            }

    def __init__(self, tableMgr, conf=None):

        self.tableMgr = tableMgr

        _conf = dict(self.default_conf)
        _conf.update(conf or {})
        self.conf = _conf
        table = _conf.get('table', 'default')
        self._table = self.tableMgr.get_table(table)

        print ("DEBUG HERE", self._table.__dict__)
        self.tableMgr.debug()

        if self._table is not None:
            print (" STARTING DNS SERVERRRRR on " + _conf['bind'] )
            resolvers = (_conf['resolvers']) if _conf['recurse'] else ()
            dns = DnsServer(_conf['bind'], self._table, resolvers)
        else:
            log ('Server did not start because no known table %s' % table)

        self.monitor = dns

        return

    def start_svc(self):

        dns = self.monitor
        gevent.signal_handler(signal.SIGINT, stop, dns)
        gevent.signal_handler(signal.SIGTERM, stop, dns)
        dns.start()


       # docker_uri = _conf['docker_socket']
       # tls_config = None
       # if docker_uri.startswith('https://'):
       #     tls_config = docker.tls.TLSConfig(verify=False)
       # try:
       #     client = docker.Client(docker_uri, version='auto', tls=tls_config)
       # except docker.errors.TLSParameterError as e:
       #     log('Docker error: %s' % e)
       #     sys.exit(1)

       # self.table = NameTable([]) #[(k + "." + conf['domain'], v) for (k, v) in args.record])
       # self.monitor = DockerMonitor(client, self.table, _conf['domain'], _conf['expose_ip'])
#      #  self.table = NameTable([(k + "." + conf['domain'], v) for (k, v) in args.record])




class DnsServer(DatagramServer):

    '''
    Answers DNS queries against the name table, falling back to the recursive
    resolver (if present).
    '''

    def __init__(self, bindaddr, table, dns_servers=None):
        DatagramServer.__init__(self, bindaddr)
        self._table = table
        self._resolver = None
        if dns_servers:
            self._resolver = Resolver(servers=dns_servers,
                timeout=DNS_RESOLVER_TIMEOUT, tries=1)

    def handle(self, data, peer):
        rec = DNSRecord.parse(data)
        addrs = set()
        names = set()
        auth = False
        if rec.q.qtype in (QTYPE.A, QTYPE.AAAA, QTYPE.ANY):
            addrs = self._table.get(rec.q.qname.idna()) or set()
            if addrs:
                auth = True
                if rec.q.qtype == QTYPE.AAAA:
                    addrs = set()
            else:
                parts = [ txt.decode() for txt in rec.q.qname.label]
                tmp = self._gethostbyname('.'.join(parts))
                if tmp is not None:
                    addrs.add(tmp)

        elif rec.q.qtype in (QTYPE.PTR,):
            key = '.'.join(rec.q.qname.label)
            names = self._table.get(key) or set()
            if not names:
                addr = '.'.join(rec.q.qname.stripSuffix('in-addr.arpa').label)
                tmp = self._gethostbyaddr(addr)
                if tmp is not None:
                    names.add(tmp)

        self.socket.sendto(self._reply(rec, auth, addrs, names), peer)

    def _reply(self, rec, auth, addrs, names):
        reply = DNSRecord(DNSHeader(id=rec.header.id, qr=1, aa=auth, ra=bool(self._resolver)), q=rec.q)
        for addr in addrs:
            reply.add_answer(RR(rec.q.qname, QTYPE.A, rdata=A(addr)))
        for name in names:
            reply.add_answer(RR(rec.q.qname, QTYPE.PTR, rdata=PTR(name)))
        return reply.pack()

    def _gethostbyname(self, name):
        if not self._resolver:
            return None
        try:
            return self._resolver.gethostbyname(name)
        except socket.gaierror as e:
            msg = str(e)
            if not contains(msg, 'ETIMEOUT', 'ENOTFOUND'):
                log(msg)

    def _gethostbyaddr(self, addr):
        if not self._resolver:
            return None
        try:
            res = self._resolver.gethostbyaddr(addr)
            if res:
                return res[0]
            return None
        except socket.gaierror as e:
            msg = str(e)
            if not contains(msg, 'ETIMEOUT', 'ENOTFOUND'):
                log(msg)



