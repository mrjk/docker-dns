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
from dnslib import A, DNSHeader, DNSLabel, DNSRecord, PTR, QTYPE, RR, CNAME
import gevent

# from gevent import monkey

from gevent import socket, threading
from gevent.server import DatagramServer
from gevent.resolver.ares import Resolver
from ipaddress import ip_network  # , ip_address

import urllib3


from dockerns.common import log, contains
from dockerns.tables import StoreTable
from dockerns.model import BackendInst

# monkey.patch_all()
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


# Plugin entrypoint
# =============


def stop(*servers):
    for svr in servers:
        if svr.started:
            svr.stop()
    sys.exit(signal.SIGINT)


class Plugin(BackendInst):
    "Store records in embedded DNS server"

    default_conf = {
        "bind": "127.0.0.1:5358",
        #'resolvers': '8.8.8.8,8.8.4.4',
        "resolvers": "8.8.8.8",
        "recurse": True,
        "records": ["default"],
        "table": "default",
    }

    store_table_name = "dnspython"

    def init_store(self):
        return NameTable([])

    def start_svc(self):
        _conf = self.conf

        log(
            "Starting dns server on: %s (%s/%s)"
            % (_conf["bind"], self.store_name, self.store_table_name)
        )
        resolvers = (_conf["resolvers"]) if _conf["recurse"] else ()
        resolvers = ()

        dns = DnsServer(_conf["bind"], self._table, resolvers)
        gevent.signal_handler(signal.SIGINT, stop, dns)
        gevent.signal_handler(signal.SIGTERM, stop, dns)

        return dns.start
        return gevent.spawn(dns.start)

        # ret = dns.start()
        # print ("IS IT EXECUTED SOMETIMES ?" , dns._spawn )
        # return dns._spawn


# Datastore Class
# =============


# Maybe this class should be stored somewhere else ...
# Should be inherited from: StoreTable
class NameTable(StoreTable):
    "Table mapping names to addresses"

    def __init__(self, records):
        self._storage = defaultdict(set)
        self._lock = threading.Lock()
        for rec in records:
            self.add(rec[0], rec[1])

        self.network_blacklist = self.gen_bl() or []

    def gen_bl(self, blacklist=None):
        "Generate blacklist"

        # temporary disabled
        return []

        network_blacklist = blacklist or os.environ.get("NETWORK_BLACKLIST")
        if not network_blacklist:
            network_blacklist = "255.255.255.255/32"

        network_blacklist = network_blacklist.split()
        for i, network in enumerate(network_blacklist):
            network_blacklist[i] = ip_network(network)

        return network_blacklist

    def debug(self):
        ret = {}  # dict(self._storage)
        for k, v in self._storage.items():
            name = ".".join([t.decode() for t in k])
            ret[name] = v

        return ret


    def add(self, record):
        domain = record.domain
        name = record.name
        # addr = record.rr

        if name.startswith("."):
            name = "*" + name

        if domain:
            name = ".".join([name, domain])

        key = self._key(name)
        if key:
            with self._lock:
                # for network in self.network_blacklist:
                #    try:
                #        if addr and ip_address(addr) in network:
                #            log(
                #                "skipping table.add %s -> %s (blacklisted network)",
                #                name,
                #                addr,
                #            )
                #            return
                #    except ValueError as err:
                #        print ("SKIPPED", addr)
                #        continue

                for addr in record.rr:
                    log("table.add %s -> %s", name, addr)
                    self._storage[key].add(addr)

                # reverse map for PTR records
                # addr = "%s.in-addr.arpa" % ".".join(reversed(addr.split(".")))
                # key = self._key(addr)
                # log("table.add %s -> %s", addr, name)
                # self._storage[key].add(name)

    def get(self, name, domain=None):
        if domain:
            name = "%s.%s" % (name, domain)

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

    def rename(self, domain, old_name, new_name):
        if not old_name or not new_name:
            return

        if domain:
            old_name = ".".join([old_name, domain])

        old_name = old_name.lstrip("/")
        old_key = self._key(old_name)
        new_key = ".".join([self._key(new_name), domain])
        with self._lock:
            self._storage[new_key] = self._storage.pop(old_key)
            log("table.rename (%s -> %s)", old_name, new_name)

    def remove(self, record, rr=None ):
        domain = record.domain
        name = record.name
        rr = rr or record.rr

        if domain:
            name = ".".join([name, domain])
        key = self._key(name)
        if key:
            with self._lock:
                
                # Remove the whole entry
                if rr is None:
                    if key in self._storage:
                        log("table.remove %s", name)
                        del self._storage[key]

                # Remove specific records
                elif key in self._storage:
                    # Remove records one by one
                    for val in rr:
                        log("table.remove %s->%s" % (name, val))
                        self._storage[key].remove(val)

                    # Cleanup empty entries
                    if not self._storage[key]:
                        del self._storage[key]


    def _key(self, name):
        try:
            label = DNSLabel(name.lower()).label
            return label
        except Exception:
            print("FAIL HERER on", name)
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
            try:
                reply.add_answer(RR(rec.q.qname, QTYPE.A, rdata=A(addr)))
            except ValueError:
                reply.add_answer(RR(rec.q.qname, QTYPE.CNAME, rdata=CNAME(addr)))

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
