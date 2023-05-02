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
#from lib.tables import NameTable

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

Container = namedtuple('Container', 'id, name, running, addrs')


from jinja2 import Template
TEMPLATE_BASE="""

{% for net_name, net_conf in cont.networks.items() -%}
{% for alias in ( net_conf.get('aliases') + cont.names ) -%}
; Configure {{ alias }}
{{ alias }} IN A {{ net_conf.get('ip') }}
{{ net_name }}.{{ alias }} IN A {{ net_conf.get('ip') }}
{% endfor %}
{%- endfor %}

{% for aliase in ( cont.names + [cont.id] ) -%}
{% for port_name, port_ip in cont.ports -%}
{% for ip in port_ip -%}
{{ port_name }}.{{ aliase }} IN A {{ ip }}
{% endfor %}
{%- endfor %}
{%- endfor %}

"""

TEMPLATE_CUSTOM="""

{% for net_name, net_conf in cont.networks.items() -%}
{% for alias in ( net_conf.get('aliases') + cont.names ) -%}
; Configure {{ alias }}
{{ alias }} IN A {{ net_conf.get('ip') }}
{{ net_name }}.{{ alias }} IN A {{ net_conf.get('ip') }}
{% endfor %}
{%- endfor %}

{% for aliase in ( cont.names + [cont.id] ) -%}
{% for port_name, port_ip in cont.ports -%}
{% for ip in port_ip -%}
{{ port_name }}.{{ aliase }} IN A {{ ip }}
{% endfor %}
{%- endfor %}
{%- endfor %}

"""




# COMMON ???
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


def parse_config(str_conf):
    "Parse config from dict or string"

    ret = {}

    if isinstance(str_conf, dict):
        for key, val in str_conf.items():
            ret[key] = val
    else:
        lines = str_conf.split(" ")
        for line in lines:
            raw = line.split("=", 2)
            key = raw[0]
            if key:
                value = ""
                if len(raw) > 1:
                    value = raw[1]
                ret[key] = value

    return ret
    #return SimpleNamespace(**ret)


# Plugin entrypoint
# =============

class Source():
    'Reads events from Docker and updates the name table'

    default_conf = {
                'tables': ['default'],
                'docker_socket': 'unix:///var/run/docker.sock',
                'expose_ip': '',
                'domain': 'tld',
            }

    def __init__(self, tableMgr, conf=None):

        self.tableMgr = tableMgr

        _conf = dict(self.default_conf)
        _conf.update(conf or {})
        self.conf = _conf
        docker_uri = _conf['docker_socket']

        self.monitor = DockerMonitor(self, docker_uri)


# Docker monitoring
# =============

class DockerMonitor():

    def __init__(self, parent, docker_uri):

        self.parent = parent

        # Create client
        tls_config = None
        if docker_uri.startswith('https://'):
            tls_config = docker.tls.TLSConfig(verify=False)
        try:
            client = docker.Client(docker_uri, version='auto', tls=tls_config)
        except docker.errors.TLSParameterError as e:
            log('Docker error: %s' % e)
            sys.exit(1)

        # Init object
        self._docker = client
        self.tableMgr = parent.tableMgr
        self._tables = parent.conf['tables']
        log ("Working with tables: %s" % self._tables )
        self._domain = parent.conf['domain'].lstrip('.')
        self._default_ip = parent.conf['expose_ip']

        #for name in self._tables:
        #    self.tableMgr.ensure(name)


#    def OLD__init__(self, parent, client, table, domain, default_ip=None):
#        self.parent = parent
#        self._docker = client
#        self._table = table
#        self._domain = domain.lstrip('.')
#        self._default_ip = default_ip


    def start(self):
        # start the event poller, but don't read from the stream yet
        events = self._docker.events()

        # bootstrap by inspecting all running containers
        for container in self._docker.containers():
            meta = self._metadata(container['Id'])
            meta2 = self._metadata_extended(container['Id'])
            #pprint (meta)
            #pprint (meta2)

            tm = Template(TEMPLATE_BASE)
            msg = tm.render(cont=meta)
            # Print templated message !
            #print (msg)


            for rec in self._inspect(container['Id']):
                if rec.running:
                    for addr in rec.addrs:
                        # WIPPP
                        self.tableMgr.add(self._tables, rec.name, addr)

        # read the docker event stream and update the name table
        for raw in events:
            evt = json.loads(raw)
            if evt.get('Type', 'container') == 'container':
                cid = evt.get('id')
                if cid is None:
                    cid = evt.get('ID')
                if cid is None:
                    continue
                status = evt.get('status')
                if status in set(('start', 'die', 'rename')):
                    try:
                        for rec in self._inspect(cid):
                            if status == 'start':
                                for addr in rec.addrs:
                                    self.tableMgr.add(self._tables, rec.name, addr)
                                    #self._table.add(rec.name, addr)

                            elif status == 'rename':
                                old_name = get(evt, 'Actor', 'Attributes', 'oldName')
                                new_name = get(evt, 'Actor', 'Attributes', 'name')
                                old_name = '.'.join((old_name, self._domain))
                                new_name = '.'.join((new_name, self._domain))
                                self.tableMgr.rename(self._tables, old_name, new_name)
                                # self._table.rename(old_name, new_name)

                            else:
                                self.tableMgr.remove(self._tables, rec.name)
                                #self._table.remove(rec.name)

                    except Exception as e:
                        log('Error: %s', e)

        ## WIPPP
        print ("DEBUG TABLLESSSSS")
        self.tableMgr.debug()
        #return

    def _get_name(self, name):
        name = RE_VALIDNAME.sub('', name).rstrip('.')
        return name

    def _get_names(self, name, labels):
        names = [ self._get_name(name) ]

        labels = labels or {}
        instance = int(labels.get('com.docker.compose.container-number', 1))
        service = labels.get('com.docker.compose.service')
        project = labels.get('com.docker.compose.project')

        if all((instance, service, project)):
            names.append('%d.%s.%s' % (instance, service, project))

            # the first instance of a service is available without number
            # prefix
            if instance == 1:
                names.append('%s.%s' % (service, project))

        return names
        return [ '.'.join((name, self._domain)) for name in names ]

    def _get_addrs(self, networks):
        return [ value['IPAddress'] for value in networks.values() ]

    #def _get_net_addrs2(self, networks):
    #    return [ {'ip': value['IPAddress'], 'aliases': value['Aliases']} for value in networks.values() ]

    def _get_net_addrs2(self, networks):
        return {name: { 'ip': value['IPAddress'], 'aliases': value['Aliases']} for name, value in networks.items()}

    def _get_net_addrs(self, networks):
        return {name: value['IPAddress'] for name, value in networks.items()}

    def _get_net_ports(self, ports):

        ports = ports or {}

        ret = []
        for port_key, port_conf in ports.items():

            # Parse key
            port_prot, port_num = None, 'tcp'
            port_parts = port_key.split('/', 2)
            if len(port_parts) == 2:
                port_num, port_prot = port_parts[0], port_parts[1]
            elif len(port_parts) == 1:
                port_num = port_parts[0]
            if not port_num:
                continue

            # Parse config
            port_ips = []
            port_conf = port_conf or []
            for ip in port_conf:
                host_ip = ip.get('HostIp')
                if host_ip in ['0.0.0.0', '::']:
                    # FAll back on requested public IP
                    host_ip = self._default_ip
                if host_ip and host_ip not in port_ips:
                    port_ips.append(host_ip)

            # Append to records
            if port_ips:
                port_rec = '%s-%s' % (port_prot, port_num)
                ret.append((port_rec, port_ips))

        return ret

    def _inspect(self, cid):
        # get full details on this container from docker
        rec = self._docker.inspect_container(cid)

        # ensure name is valid, and append our domain
        name = get(rec, 'Name')
        if not name:
            return None

        id_ = get(rec, 'Id')
        labels = get(rec, 'Config', 'Labels')
        state = get(rec, 'State', 'Running')

        networks = get(rec, 'NetworkSettings', 'Networks')
        ip_addrs = self._get_addrs(networks)
        ports = get(rec, 'NetworkSettings', 'Ports')
        ports = self._get_net_ports(ports)
        hostname = '%s.%s' % (get(rec, 'Config', 'Hostname'), self._domain)

        ret = [ Container(id_, hostname, state, ip_addrs) ]
        for alias in self._get_names(name, labels):
            ret.append(Container(id_, alias, state, ip_addrs))

            # Loop over each networks
            for net_name, net_ip in self._get_net_addrs(networks).items():
                net_alias = '%s.%s' % (net_name, alias)
                ret.append(
                        Container(id_, net_alias, state, [net_ip])
                        )

            # Loop over each ports
            for port_key, port_ips in ports:
                port_rec = '%s.%s' % (port_key, alias)
                ret.append(
                        Container(id_, port_rec, state, port_ips)
                        )

        return ret

    def _metadata_extended(self, cid):
        # get full details on this container from docker
        rec = self._docker.inspect_container(cid)

        # ensure name is valid, and append our domain
        name = get(rec, 'Name')
        if not name:
            return None

        meta = self._metadata(cid)
        labels = get(rec, 'Config', 'Labels')

        ret = {}
        prefix = 'dockerns'
        for name, value in labels.items():
            if not name.startswith(prefix):
                continue

            # Split key label
            parts = name.split('.', 3)
            instance = 'docker'
            name = None
            if len(parts) == 3:
                instance = parts[1]
                name = parts[2]
            elif len(parts) == 2:
                instance = parts[1]

            conf = {
                    "instance": instance,
                    "name": name,
                    }

            #pprint (parse_config(value))

            conf.update(parse_config(value))
            ret[instance] = conf

        meta['custom'] = ret

        return meta

    def _metadata(self, cid):
        # get full details on this container from docker
        rec = self._docker.inspect_container(cid)

        # ensure name is valid, and append our domain
        name = get(rec, 'Name')
        if not name:
            return None

        uuid = get(rec, 'Id')
        id_ = uuid[:12]
        labels = get(rec, 'Config', 'Labels')
        state = get(rec, 'State', 'Running')

        networks = get(rec, 'NetworkSettings', 'Networks')
        ip_addrs = self._get_addrs(networks)
        ports = get(rec, 'NetworkSettings', 'Ports')
        ports = self._get_net_ports(ports)
        hostname = '%s.%s' % (get(rec, 'Config', 'Hostname'), self._domain)

        ret = {
                'uuid': uuid,
                'id': id_,
                'name': self._get_name(name),
                'state': state,
                'ip_addrs': ip_addrs,
                'networks': self._get_net_addrs2(networks),
                'ports': ports,
                'names': self._get_names(name, labels),
            }

        return ret

