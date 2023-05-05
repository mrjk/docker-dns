"Embedded DNS server"

# core
import os
import re
import sys
import signal
import gevent
import sys
from collections import defaultdict
from builtins import str

from pprint import pprint

# libs
from dnslib import A, DNSHeader, DNSLabel, DNSRecord, PTR, QTYPE, RR, CNAME

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

DNS_RESOLVER = ["8.8.8.8"]
DNS_RESOLVER_TIMEOUT = 3.0


# Plugin entrypoint
# =============



class Plugin(BackendInst):
    "Store records in embedded DNS server"

    default_conf = {
        "bind": "0.0.0.0:53",
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

        def stop(*servers):
            for svr in servers:
                if svr.started:
                    svr.stop()
            sys.exit(signal.SIGINT)


        dns = DnsServer(_conf["bind"], self._table, resolvers)
        gevent.signal_handler(signal.SIGINT, stop, dns)
        gevent.signal_handler(signal.SIGTERM, stop, dns)

        return dns.start


# Datastore Class
# =============


# Maybe this class should be stored somewhere else ...
# Should be inherited from: StoreTable
class NameTable(StoreTable):
    "Table mapping names to addresses"

    def __init__(self, records):
        self._db = defaultdict(set)
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
        "Dump content of the DB"
        ret = {}
        for k, v in self._db.items():
            name = ".".join([t.decode() for t in k])
            ret[name] = v

        return ret

    def add(self, record):
        "Add record to DB"

        domain = record.domain
        name = record.name

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
                    #log("table.add %s -> %s", name, addr)
                    self._db[key].add(addr)

    def get(self, name, domain=None):
        "Retrieve record from DB"

        if domain:
            name = "%s.%s" % (name, domain)

        key = self._key(name)
        if key:
            with self._lock:
                res = self._db.get(key)

                wild = re.sub(r"^[^\.]+", "*", name)
                wildkey = self._key(wild)
                wildres = self._db.get(wildkey)

                if res:
                    pass
                    log(
                        "table.get %s with %s" % (name, ", ".join(addr for addr in res))
                    )
                elif wildres:
                    #log(
                    #    "table.get %s with %s"
                    #    % (name, ", ".join(addr for addr in wildres))
                    #)
                    res = wildres
                #else:
                #    log("table.get %s with NoneType" % (name))

                #res = res or ['5.5.5.5']
                return res

    def rename(self, domain, old_name, new_name):
        "Rename record from DB"

        if not old_name or not new_name:
            return

        if domain:
            old_name = ".".join([old_name, domain])

        old_name = old_name.lstrip("/")
        old_key = self._key(old_name)
        new_key = ".".join([self._key(new_name), domain])
        with self._lock:
            self._db[new_key] = self._db.pop(old_key)
            #log("table.rename (%s -> %s)", old_name, new_name)

    def remove(self, record, rr=None):
        "Remove record from DB"
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
                    if key in self._db:
                        #log("table.remove %s", name)
                        del self._db[key]

                # Remove specific records
                elif key in self._db:
                    target = self._db[key]

                    # Remove records one by one
                    for val in rr:
                        #log("table.remove %s->%s" % (name, val))
                        try:
                            target.remove(val)
                        except KeyError:
                            log("table.remove Failed to remove: %s->%s" % (name, val))

                        #self._db[key].remove(val)

                    # Cleanup empty entries
                    #if not self._db[key]:
                    #    del self._db[key]

    def _key(self, name):
        "Retrieve a domain key"

        try:
            label = DNSLabel(name.lower()).label
            #print ("LABEL", label)
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
        "Handle DNS replies"


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
            #key = ".".join([ str(x) for x in rec.q.qname.label])
            key = ".".join(rec.q.qname.label)
            names = self._table.get(key) or set()
            if not names:
                #addr = ".".join([ str(x) for x in rec.q.qname.stripSuffix("in-addr.arpa").label])
                addr = ".".join(rec.q.qname.stripSuffix("in-addr.arpa").label)
                tmp = self._gethostbyaddr(addr)
                if tmp is not None:
                    names.add(tmp)

        #pprint (rec.q.qname.label)
        peer_ip = peer[0]
        self.socket.sendto(self._reply(rec, auth, addrs, names, peer_ip), peer)

    def _reply(self, rec, auth, addrs, names, peer_ip):
        "Craft DNS replies"

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

        #log ("dns.embedded Answers %s: %s: %s" % (peer_ip, ', '.join([ str( '.'.join(ques._qname.label.decode()) ) for ques in reply.questions ]), None )) #reply.rr))
        log ("dns.embedded Answers %s" % peer_ip)
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
