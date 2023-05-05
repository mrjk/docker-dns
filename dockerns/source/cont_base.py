"Docker monitoring"

import sys
import json
import re
from types import SimpleNamespace

from pprint import pprint

# libs
import docker
import urllib3
from jinja2 import Template
import jinja2

# from jinja2 import Template

from collections import namedtuple
from dockerns.common import log, get
from dockerns.tables import Record
from dockerns.model import SourceInst

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


RE_VALIDNAME = re.compile("[^\w\d.-]")

TEMPLATE_BASE = """

{% for net_name, net_conf in cont.networks_by_name.items() -%}
{% for alias in net_conf.get('aliases') -%}
;{{ domain }};{{ alias }};A;{{ net_conf.get('ip') }}
;{{ domain }};{{ net_name }}.{{ alias }};A;{{ net_conf.get('ip') }}
;in-addr.arpa;{{ net_conf.get('ip')|reverse_ip  }};PTR;{{ alias }}.{{ domain }}.
;in-addr.arpa;{{ net_conf.get('ip')|reverse_ip }};PTR;{{ net_name }}.{{ alias }}.{{ domain }}.
;in-addr.arpa;{{ net_conf.get('ip')|reverse_ip  }};A;{{ alias }}.{{ domain }}.
;in-addr.arpa;{{ net_conf.get('ip')|reverse_ip }};A;{{ net_name }}.{{ alias }}.{{ domain }}.
{% endfor %}
{%- endfor %}

{% for aliase in cont.aliases -%}
{% for port_name, port_conf in cont.ports_by_name.items() -%}
{% for ip in port_conf.ips -%}
;{{ domain }};{{ port_name }}.{{ aliase }};A;{{ ip }}
{% if aliase == cont.name %}
;in-addr.arpa;{{ ip | reverse_ip }};PTR;{{ port_name }}.{{ aliase }}.{{ domain }}.
{% endif %}
{% endfor %}
{%- endfor %}
{%- endfor %}

"""

TEMPLATE_EXTENDED = TEMPLATE_BASE + """
{% for key, value in cont.labels.items() if key.startswith('dockerns') -%}
{% set conf = value | parse_kv %}
{% set prefix = [conf.domain|d(domain), conf.record|d(cont.name), conf.type|d('A')]|join(';') %}
{% set conf_data = conf.data|d('cont.networks_ips') %}
;{{ prefix }};{{ conf_data }}
{%- endfor -%}
"""




# Plugin entrypoint
# =============


class Plugin(SourceInst):
    "Reads events from Docker and updates the name table"

    default_conf = {
        "tables": ["default"],
        "docker_socket": "unix:///var/run/docker.sock",
        "expose_ip": "",
        "domain": "docker",
    }

    def start_svc(self):
        docker_uri = self.conf["docker_socket"]
        mon = DockerMonitor(self, docker_uri)

        return mon.start


# Docker monitoring
# =============

RecordConfig = namedtuple("record", ["domain", "name", "type", "rr","links"])


def parse_params(str_conf):
    "Parse params from string"

    ret = {}
    lines = str_conf.split(",")
    for line in lines:
        raw = line.split(":", 2)
        key = raw[0]
        if key:
            value = ""
            if len(raw) > 1:
                value = raw[1]
            ret[key] = value.strip()

    return ret

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


def reverse_ip(addr):
    """Filter to get reversed IP"""
    return '.'.join(reversed(addr.split('.')))

def reverse_ip_ptr(addr):
    """Filter to get reverse pointer"""
    addr = '%s.in-addr.arpa' % reverse_ip(addr)
    return addr



def _merge_list_uniq(*args):
    "Merge many lists and remove all duplicates"
    ret = []
    for item in args:
        if isinstance(item, list):
            ret.extend(item)
    return list(set(ret))


def list_flaten(obj):
    "Always returns a list of strings"

    if isinstance(obj, list):
        return [str(x) for x in obj]
    elif isinstance(obj, dict):
        return list(set(obj.keys()))
    else:
        return [str(obj)]

def deep_get(obj, *keys, strict=True):
    "Access to nested object programmatically"

    # Parse args
    if len(keys) == 0:
        assert False
    elif len(keys) == 1:
        keys = keys[0]
        if isinstance(keys, str):
            keys = keys.split('.')


    ret = obj
    for key in keys:
        if hasattr(ret, key):
            ret = getattr(ret, key)
        elif hasattr(ret, 'get') and key in ret:
            ret = ret.get(key)
        else:
            index = int(key)
            if 0 <= index < len(ret):
                ret = ret[index]
            else:

                if strict:
                    raise Exception("Missing key '{key}' in '{keys}' for {obj}")
                else:
                    return ret

    return ret




class DBCont():

    def __init__(self, client):
        self._db = {}
        self._docker = client
        #self._store = store

        # Autofill
        for container in client.containers():
            cid = container["Id"]
            self.add_by_id(cid)

    def get_by_id(self, cid):

        # Look first in local DB
        if cid in self._db:
            return self._db[cid]

        # Then fetch from docker
        container =  self._docker.inspect_container(cid)
        cont = ContainerInspect(container, container_db=self)
        return cont

    def add_by_id(self, cid):
        cont = self.get_by_id(cid)
        self._db[cid] = cont

    #def add(self, cont):
    #    cid = cont.uuid
    #    self._db[cid] = cont

    def remove_by_id(self, id_):
        if id_ in self._db:
            del self._db[id_]

    def list(self):
        return self._db.values()

    def _search(self, name, extract=None):
        ret = []
        for id_, cont in self._db.items():
            if name in cont.aliases:
                ret.append(cont)

        if extract:
            ret2 = []
            for cont in ret:
                value = deep_get(cont.__dict__, *extract)
                ret2.append(value)
            return ret2
        return ret


    def search(self, pattern):

        parts = pattern.split(':')

        target = parts[0]
        name = parts[1]
        extract = None
        if len(parts) > 2:
            extract = parts[2:]

        if target == 'container':
            return self._search(name, extract=extract)
            #return self.search2(name)
        return f"FAILED RESOPLUTIO: {target} || {name}"


    def dump(self):

        db = {}
        for id_, cont in self._db.items():

            db[id_] = cont
            #pprint (cont)
            for alias in cont.aliases:
                db[alias] = cont

        return db


        #for part in parts.split(':'):


class ContainerRecords:
    "A class to generate container records"


    def get_template(self, template_name, extra_filters=None):
        loader = jinja2.DictLoader({
                    'base': TEMPLATE_BASE,
                    'extended': TEMPLATE_EXTENDED
                 })
        env = jinja2.Environment(autoescape=True, loader=loader)

        if extra_filters:
            env.filters.update(extra_filters)
        
        return env.get_template(template_name)


    # Record output
    # -----------------
    def get_records(self, domain=None):
        "Get full details on this container from docker"

        cont_db = self._cont_db

        # Fetch metadata
        domain = domain or self._domain
        meta = SimpleNamespace(**self._meta)

        # Fetch template

        extra_filters = {
            'reverse_ip': reverse_ip,
            'reverse_ptr': reverse_ip_ptr,
            'parse_kv': parse_config,
            'parse_params': parse_params,
            #'resolve': cont_db.search,
            #'parse_rr': parse_rr,
                }
        temp = self.get_template('extended', extra_filters=extra_filters)
        msg = temp.render(cont=meta, domain=domain, cont_db=cont_db)

        ret = []
        #print (msg)
        for line in msg.split('\n'):
            if not line.startswith(';'):
                continue
            params = line.split(';')[1:]
            size = len(params)
            SIZE = 5
            if size == 1:
                continue
            elif size != SIZE:
                while len(params) < SIZE:
                    params.append('')

            assert len(params) == SIZE
            record = RecordConfig(*params)

            # Build links and reference
            db = self._resolve_data_links(record.links, cont_db)
            _rr = self._resolve_data_ref(record.rr, db)

            try:
                rec = Record(owner=meta.uuid, 
                       name=record.name,
                       domain=record.domain,
                       rr=_rr,
                       kind=record.type)
                ret.append(rec)
            except TypeError:
                log("Ignore record: %s" % line )

        if not ret and msg.strip():
            #pprint(meta)
            log("Failed to parse records:")
            log('--' * 20)
            print (msg)
            log('--' * 20)
        #else:
        #    pprint (ret)

        return ret


    def _resolve_data_links(self, links, db=None):
            links = list(set(['self:self'] + links.split(',')))
            linked = {}
            for link in links:
                if link and ':' in link:
                    parts = link.split(':', 2)
                    target = parts[0]
                    if target == 'self':
                        target = self
                    else:
                        target = db.search(target)

                    linked[parts[1]] = target

            return linked

    def _resolve_data_ref(self, text, db=None):
        "Resolve custom reference"

        db = db or {}
        ret = []
        for item in text.split(','):

            parts = item.split('.')

            if parts[0] in db:
                name = parts[0]
                obj = db[name]
                out = deep_get(obj, parts[1:])
                for flattened in list_flaten(out):
                    ret.append(flattened)
            else:
                ret.append(str(item))

        assert isinstance(ret, list), f"Got: {ret}"
        return ret




class ContainerInspect(ContainerRecords):
    "Expose container metadata"

    #def __init__(self, storeMgr, container):
    def __init__(self, container, container_db ):
        self.container = container
 #       self.storeMgr = storeMgr
        self._cont_db = container_db

        self._domain = ""
        self._default_ip = "1.2.3.4"


        # Do metadata
        self._meta = self._metadata()
        # pprint(self._meta)
        for key, val in self._meta.items():
            setattr(self, key, val)


    # Metadata extraction v2
    # -----------------
    def _metadata(self, extended=True):
        "Get full details on this container from docker"
        rec = self.container

        # ensure name is valid, and append our domain
        name = get(rec, "Name")
        if not name:
            print("FAIL", name, type(rec))
            return None

        # Base settings
        uuid = get(rec, "Id")
        raw_labels = get(rec, "Config", "Labels") or {}
        raw_networks = get(rec, "NetworkSettings", "Networks")
        raw_ports = get(rec, "NetworkSettings", "Ports")

        # Process names, networks and ports
        conf_base = self._get_cont_base(uuid, name, raw_labels)
        conf_net = self._get_networks_by(raw_networks, default_aliases=conf_base['aliases'])
        conf_port = self._get_net_ports_by(raw_ports, default_ip=self._default_ip)

        # Update metadata output
        ret = {
            "running": get(rec, "State", "Running"),
            "hostname": get(rec, "Config", "Hostname"),
            "labels": raw_labels,
        }
        ret.update(conf_base)
        ret.update(conf_net)
        ret.update(conf_port)

        if False and extended:
            ret = self._metadata_extended(ret)

        return ret


    # Container Base
    # ==========================

    def _get_cont_base(self, uuid, name, labels, autoresolve=True):
        "Return container valid names, first name is main name"

        # Base calculation
        id_ = uuid[:12]
        real_name = self._get_name(name)

        # Compose specification
        labels = labels or {}
        compose_instance = labels.get("com.docker.compose.container-number")
        compose_service = labels.get("com.docker.compose.service")
        compose_project = labels.get("com.docker.compose.project")

        # Auto resolver
        if autoresolve and not all((compose_instance, compose_service, compose_project)):
            compose_project, compose_service, compose_instance = self._process_name(real_name)

        # FQN
        if compose_project:
            dotted_name = "%s.%s.%s" % (compose_instance, compose_service, compose_project)
            dotted_service = "%s.%s" % (compose_service, compose_project)
        else:
            dotted_name = "%s.%s" % (compose_instance, compose_service)
            dotted_service = "%s" % (compose_service)

        # Output
        return {
                "id": id_,
                "uuid": uuid,
                "name": real_name,
                "names": [id_, compose_service, real_name],
                "aliases": [id_, compose_service, real_name, dotted_name, dotted_service,],

                "project": compose_project,
                "service":  compose_service,
                "instance":  compose_instance,

                "name_fqn" : dotted_name,
                "service_fqn": dotted_service,
                }

    def _get_name(self, name):
        "Get container main name"
        name = RE_VALIDNAME.sub("", name).rstrip(".")
        return name

    def _process_name(self, name):

        parts = name.split('-')
        project = ''
        instance = ''
        if len (parts) == 2:
            #last = parts[1]
            last = parts[-1]
            try:
                instance = int(last)
                name = parts[0]
            except ValueError:
                project = parts[0]
                name = last
        elif len (parts) > 2:
            last = parts[-1]
            try:
                project = parts[0]
                name = '-'.join(parts[1:-1])
                instance = int(last)
            except ValueError:
                project = parts[0]
                name = '-'.join(parts[1:-1])

        instance = instance or 1
        return project, name, instance
        return {
                "last": last,
                "parts": parts,
                "name": name,
                "project": project,
                "instance": instance
                }



    # Container networking
    # ==========================

    def _get_networks_by(self, networks, default_aliases=None):

        networks_by_ip = self._get_networks_ip(networks, default_aliases=default_aliases)
        networks_by_name = self._get_networks_name(networks, default_aliases=default_aliases)
        networks_by_alias = self._get_networks_alias(networks, default_aliases=default_aliases)

        return {
            "networks_by_ip": networks_by_ip,
            "networks_by_name": networks_by_name,
            "networks_by_alias": networks_by_alias,

            "networks_ips": list(set(networks_by_ip.keys())),
            "networks_names": list(set(networks_by_name.keys())),
            "networks_aliases": list(set(networks_by_alias.keys())),
            }

    def _get_networks_name(self, networks, default_aliases=None):
        "Get all container network names"
        return {
            name: {"ip": value["IPAddress"], "aliases": _merge_list_uniq(value["Aliases"], default_aliases )}
            for name, value in networks.items()
        }
    def _get_networks_ip(self, networks, default_aliases=None):
        "Get all container ips"
        return {
            value["IPAddress"]: {"network": name, "aliases": _merge_list_uniq(value["Aliases"], default_aliases ) }
            for name, value in networks.items()
        }
    def _get_networks_alias(self, networks, default_aliases=None):
        "Get all container network aliases"
        ret = {}
        for name, value in networks.items():
            aliases = _merge_list_uniq(value["Aliases"], default_aliases )
            for alias in aliases:
                if not alias in ret:
                    ret[alias] = []
                ret[alias].append({"network": name, "ip": value["IPAddress"]})
        return ret



    # Container Ports
    # ==========================

    def _get_net_ports_by(self, ports, default_ip=None):
        "Get container ports"
        ports = ports or {}
        ret_by_ip = {}
        ret_by_name = {}
        for port_key, port_conf in ports.items():

            # Parse key
            port_prot, port_num = None, "tcp"
            port_parts = port_key.split("/", 2)
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
                host_ip = ip.get("HostIp")
                if host_ip in ["0.0.0.0", "::"]:
                    # Fall back on requested public IP
                    host_ip = default_ip
                if host_ip and host_ip not in port_ips:
                    port_ips.append(host_ip)

            # Build config
            conf = SimpleNamespace(**{
                    "prot": port_prot,
                    "num": port_num,
                    "ips": port_ips,
                    "name": "%s-%s" % (port_prot, port_num),
                    })

            # Append to records
            if conf.ips:
                ret_by_name[conf.name] = { key: val for key, val in conf.__dict__.items() if key != 'name' }
                for ip in conf.ips:
                    if not ip in ret_by_ip:
                        ret_by_ip[ip] = []
                    ret_by_ip[ip].append({ key: val for key, val in conf.__dict__.items() if key != 'ips' })

        # Return results
        ret = {    
                "ports_by_name": ret_by_name,
                "ports_by_ip": ret_by_ip,

                "ports_names": list(set(ret_by_name.keys())),
                "ports_ips": list(set(ret_by_ip.keys())),
                }
        return ret



class DockerMonitor:
    def __init__(self, parent, docker_uri):
        self.parent = parent

        # Create client
        tls_config = None
        if docker_uri.startswith("https://"):
            tls_config = docker.tls.TLSConfig(verify=False)
        try:
            client = docker.Client(docker_uri, version="auto", tls=tls_config)
        except docker.errors.TLSParameterError as e:
            log("Docker error: %s" % e)
            sys.exit(1)
        except Exception as e:
            log("Docker error: %s" % e)
            sys.exit(1)

        # Init object
        self._db_cont = DBCont(client)
        self._docker = client
        self.storeMgr = parent.storeMgr
        self._tables = parent.conf["tables"]
        log("Working with tables: %s" % self._tables)
        self._domain = parent.conf["domain"].lstrip(".")
        #self._default_ip = parent.conf["expose_ip"]

    def start(self):
        "Listen docker events"

        # Start the event poller, but don't read from the stream yet
        events = self._docker.events()

        # Bootstrap by inspecting all running containers
        for cont in self._db_cont.list():
            with self.storeMgr.session(self._tables) as store:
                for rec in cont.get_records(domain=self._domain):
                    store.add(self._tables, rec)

        # read the docker event stream and update the name table
        for raw in events:
            evt = json.loads(raw)

            if evt.get("Type", "container") == "container":
                cid = evt.get("id")
                if cid is None:
                    cid = evt.get("ID")
                if cid is None:
                    continue
                status = evt.get("status")
                log("new '%s' event on %s: %s" % (status, evt.get("Type"), cid))

                self._event_container(cid, status, evt)

    def _event_container(self, cid, status, evt):
        changed = False

        if status in set(("start", "rename")):
            changed = True
            cont = self._db_cont.get_by_id(cid)

            for rec in cont.get_records(domain=self._domain):
                if status == "start":
                    self.storeMgr.add(self._tables, rec)
                elif status == "rename":
                    old_name = get(evt, "Actor", "Attributes", "oldName")
                    new_name = get(evt, "Actor", "Attributes", "name")
                    # old_name = ".".join((old_name, rec.domain))
                    # new_name = ".".join((new_name, rec.domain))
                    self.storeMgr.rename(self._tables, rec.domain, old_name, new_name)

        elif status == "die":
            changed = True
            self._db_cont.remove_by_id(cid)

            old_records = self.storeMgr.query(self._tables, owner=cid, aggregate=True)
            with self.storeMgr.session(self._tables) as store:
                for store_name, records in old_records.items():
                    for rec in records:
                        store.remove([store_name], rec)
        #if changed:
        #    log("Dump table content changes: %s" % status)
        #    self.storeMgr.debug()
