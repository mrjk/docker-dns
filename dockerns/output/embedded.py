#!/usr/bin/env python


# dockerdns - simple, automatic, self-contained dns server for docker

# monkey patch everything


# core
import os
import re
import sys
import signal
from collections import defaultdict
from builtins import str

from pprint import pprint

# libs
from dnslib import A, DNSHeader, DNSLabel, DNSRecord, PTR, QTYPE, RR
import gevent
from gevent import monkey

from gevent import socket, threading
from gevent.server import DatagramServer
from gevent.resolver.ares import Resolver
from ipaddress import ip_network, ip_address

import urllib3


from dockerns.common import log, contains

monkey.patch_all()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Import local libs


# from lib.tables import NameTable

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

network_blacklist = os.environ.get("NETWORK_BLACKLIST")
if not network_blacklist:
    network_blacklist = "255.255.255.255/32"

network_blacklist = network_blacklist.split()
for i, network in enumerate(network_blacklist):
    network_blacklist[i] = ip_network(network)


def stop(*servers):
    for svr in servers:
        if svr.started:
            svr.stop()
    sys.exit(signal.SIGINT)


# Datastore Class
# =============


# Maybe this class should be stored somewhere else ...
class NameTable:
    "Table mapping names to addresses"

    def __init__(self, records):
        self._storage = defaultdict(set)
        self._lock = threading.Lock()
        for rec in records:
            self.add(rec[0], rec[1])

    def debug(self):
        ret = {}  # dict(self._storage)
        for k, v in self._storage.items():
            name = ".".join([t.decode() for t in k])
            ret[name] = v

        return ret

    def add(self, name, addr):
        if name.startswith("."):
            name = "*" + name
        key = self._key(name)
        if key:
            with self._lock:
                for network in network_blacklist:
                    if addr and ip_address(addr) in network:
                        log(
                            "skipping table.add %s -> %s (blacklisted network)",
                            name,
                            addr,
                        )
                        return
                log("table.add %s -> %s", name, addr)
                self._storage[key].add(addr)

                # reverse map for PTR records
                addr = "%s.in-addr.arpa" % ".".join(reversed(addr.split(".")))
                key = self._key(addr)
                log("table.add %s -> %s", addr, name)
                self._storage[key].add(name)

    def get(self, name):
        key = self._key(name)
        if key:
            with self._lock:
                res = self._storage.get(key)

                wild = re.sub(r"^[^\.]+", "*", name)
                wildkey = self._key(wild)
                wildres = self._storage.get(wildkey)

                if res:
                    log(
                        "table.get %s with %s" % (name, ", ".join(addr for addr in res))
                    )
                elif wildres:
                    log(
                        "table.get %s with %s"
                        % (name, ", ".join(addr for addr in wildres))
                    )
                    res = wildres
                else:
                    log("table.get %s with NoneType" % (name))
                return res

    def rename(self, old_name, new_name):
        if not old_name or not new_name:
            return
        old_name = old_name.lstrip("/")
        old_key = self._key(old_name)
        new_key = self._key(new_name)
        with self._lock:
            self._storage[new_key] = self._storage.pop(old_key)
            log("table.rename (%s -> %s)", old_name, new_name)

    def remove(self, name):
        key = self._key(name)
        if key:
            with self._lock:
                if key in self._storage:
                    log("table.remove %s", name)
                    del self._storage[key]

    def _key(self, name):
        try:
            label = DNSLabel(name.lower()).label
            return label
        except Exception:
            return None


# DNS server
# =============


class DnsServer(DatagramServer):

    """
    Answers DNS queries against the name table, falling back to the recursive
    resolver (if present).
    """

    def __init__(self, bindaddr, table, dns_servers=None):
        DatagramServer.__init__(self, bindaddr)
        self._table = table
        self._resolver = None
        if dns_servers:
            self._resolver = Resolver(
                servers=dns_servers, timeout=DNS_RESOLVER_TIMEOUT, tries=1
            )

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
                parts = [txt.decode() for txt in rec.q.qname.label]
                tmp = self._gethostbyname(".".join(parts))
                if tmp is not None:
                    addrs.add(tmp)

        elif rec.q.qtype in (QTYPE.PTR,):
            key = ".".join(rec.q.qname.label)
            names = self._table.get(key) or set()
            if not names:
                addr = ".".join(rec.q.qname.stripSuffix("in-addr.arpa").label)
                tmp = self._gethostbyaddr(addr)
                if tmp is not None:
                    names.add(tmp)

        self.socket.sendto(self._reply(rec, auth, addrs, names), peer)

    def _reply(self, rec, auth, addrs, names):
        reply = DNSRecord(
            DNSHeader(id=rec.header.id, qr=1, aa=auth, ra=bool(self._resolver)), q=rec.q
        )
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
            if not contains(msg, "ETIMEOUT", "ENOTFOUND"):
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
            if not contains(msg, "ETIMEOUT", "ENOTFOUND"):
                log(msg)


# Plugin entrypoint
# =============


class Output:
    "Store records in embedded DNS server"

    default_conf = {
        "bind": "127.0.0.1:53",
        #'resolvers': '8.8.8.8,8.8.4.4',
        "resolvers": "8.8.8.8",
        "recurse": True,
        "records": ["default"],
        "table": "default",
    }

    def __init__(self, tableMgr, conf=None):
        self.tableMgr = tableMgr
        _conf = dict(self.default_conf)
        _conf.update(conf or {})
        self.conf = _conf

        # Create table
        self.create_table()

    def create_table(self):
        # Get table
        table_name = self.conf.get("table", "default")
        self.table_name = table_name

        # Add methods
        table = self.tableMgr.ensure(table_name)
        pprint(table)
        table._tables["dnspython"] = NameTable([])
        self._table = table._tables["dnspython"]

    def start_svc(self):
        _conf = self.conf

        log(
            "Starting dns server on: %s (%s/dnspython)"
            % (_conf["bind"], self.table_name)
        )
        resolvers = (_conf["resolvers"]) if _conf["recurse"] else ()

        dns = DnsServer(_conf["bind"], self._table, resolvers)
        gevent.signal_handler(signal.SIGINT, stop, dns)
        gevent.signal_handler(signal.SIGTERM, stop, dns)
        dns.start()
