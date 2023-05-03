"Docker monitoring"

import sys
import json
import re
from types import SimpleNamespace

from pprint import pprint

# libs
import docker
import urllib3

# from jinja2 import Template

from dockerns.common import log, get
from dockerns.tables import Record
from dockerns.model import SourceInst

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


RE_VALIDNAME = re.compile("[^\w\d.-]")


TEMPLATE_BASE = """

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


class ContainerInspect:
    "Expose container metadata"

    def __init__(self, storeMgr, container):
        self.container = container
        self.storeMgr = storeMgr

        self._domain = ""
        self._default_ip = "1.2.3.4"

        self.metadata()

    # Record output
    # -----------------
    def get_records(self, domain=None):
        "Get full details on this container from docker"

        per_networks = True
        per_ports = True
        # save_meta = False
        do_reverses = True

        meta = SimpleNamespace(**self.metadata())
        domain = domain or self._domain
        assert isinstance(domain, str)

        # pprint (meta)

        # ensure name is valid, and append our domain
        name = meta.name
        if not name:
            return []
        id_ = meta.uuid
        if meta.running is not True:
            return []

        # Parse logic
        retNew = [
            Record(owner=id_, name=meta.hostname, domain=domain, rr=meta.ip_addrs)
        ]
        for alias in self._get_names(name, meta.labels):
            retNew.append(
                Record(owner=id_, name=alias, domain=domain, rr=meta.ip_addrs)
            )

            if per_networks:
                # Loop over each networks
                for net_name, net_ip in self._get_net_addrs(meta.raw_networks).items():
                    net_alias = "%s.%s" % (net_name, alias)
                    retNew.append(
                        Record(owner=id_, name=net_alias, domain=domain, rr=[net_ip])
                    )

            if per_ports:
                # Loop over each ports
                for port_key, port_ips in meta.ports:
                    port_rec = "%s.%s" % (port_key, alias)
                    retNew.append(
                        Record(owner=id_, name=port_rec, domain=domain, rr=port_ips)
                    )

        # Generate reverse
        if do_reverses:
            arpa = []
            for record in retNew:
                for addr in record.rr:
                    rev_addr = ".".join(reversed(addr.split(".")))
                    recNew = Record(
                        owner=id_,
                        name=rev_addr,
                        domain="in-addr.arpa",
                        rr=[record.name + domain],
                    )
                    arpa.append(recNew)

            retNew.extend(arpa)

        # Save recorded
        # if save_meta:
        #    ret2 = []
        #    for record in ret:
        #        # record.name
        #        # record.domain
        #        # record.addrs

        #        name = "meta.%s" % meta.hostname  # record.name
        #        # print ("ADD RECORD", name, record.name, record.addrs)
        #        ret2.append(rec)

        #    ret.extend(ret2)

        return retNew

    def _get_net_addrs(self, networks):
        return {name: value["IPAddress"] for name, value in networks.items()}

    # Metadata extraction
    # -----------------

    def metadata(self, extended=True):
        "Get full details on this container from docker"
        rec = self.container

        # ensure name is valid, and append our domain
        name = get(rec, "Name")
        if not name:
            print("FAIL", name, type(rec))
            return None

        uuid = get(rec, "Id")
        id_ = uuid[:12]
        labels = get(rec, "Config", "Labels") or {}
        state = get(rec, "State", "Running")

        networks = get(rec, "NetworkSettings", "Networks")
        ip_addrs = self._get_addrs(networks)
        assert ip_addrs, "Missing address for container !!!"
        ports = get(rec, "NetworkSettings", "Ports")
        ports = self._get_net_ports(ports)

        hostname = get(rec, "Config", "Hostname")

        ret = {
            "uuid": uuid,
            "id": id_,
            "name": self._get_name(name),
            "running": state,
            "ip_addrs": ip_addrs,
            "networks": self._get_net_addrs2(networks),
            "ports": ports,
            "names": self._get_names(name, labels),
            # TEMP
            "hostname": hostname,
            "labels": labels,
            "raw_networks": networks,
        }

        if False and extended:
            ret = self._metadata_extended(ret)

        return ret

    def _metadata_extended(self, meta):
        "Get full details on this container from docker"

        labels = meta["labels"]

        ret = {}
        prefix = "dockerns"
        for name, value in labels.items():
            if not name.startswith(prefix):
                continue

            # Split key label
            parts = name.split(".", 3)
            instance = "default"
            name = None
            if len(parts) == 3:
                instance = parts[1]
                name = parts[2]
            elif len(parts) == 2:
                instance = parts[1]

            conf = {
                "instance": instance,
                "name": name,
                "type": "A",
                "uuid": meta["uuid"],
            }
            conf.update(parse_config(value))
            # rr = conf.get('data', None)
            # if rr is None:
            #    rr = '3.2.1.4'

            # Save result
            ret[instance] = conf

        meta["custom"] = ret

        return meta

    def _get_name(self, name):
        "Get container main name"
        name = RE_VALIDNAME.sub("", name).rstrip(".")
        return name

    def _get_names(self, name, labels):
        "Return container valid names, first name is main name"
        names = [self._get_name(name)]

        labels = labels or {}
        instance = int(labels.get("com.docker.compose.container-number", 1))
        service = labels.get("com.docker.compose.service")
        project = labels.get("com.docker.compose.project")

        if all((instance, service, project)):
            names.append("%d.%s.%s" % (instance, service, project))

            # the first instance of a service is available without number
            # prefix
            if instance == 1:
                names.append("%s.%s" % (service, project))

        return names

    def _get_addrs(self, networks):
        "Get all docker ip addresses"
        return [value["IPAddress"] for value in networks.values()]

    def _get_net_addrs2(self, networks):
        "Get all container ip and aliases per networks"
        return {
            name: {"ip": value["IPAddress"], "aliases": value["Aliases"]}
            for name, value in networks.items()
        }

    def _get_net_ports(self, ports):
        "Get container ports"
        ports = ports or {}

        ret = []
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
                    # FAll back on requested public IP
                    host_ip = self._default_ip
                    # host_ip = "1.2.3.4"
                if host_ip and host_ip not in port_ips:
                    port_ips.append(host_ip)

            # Append to records
            if port_ips:
                port_rec = "%s-%s" % (port_prot, port_num)
                ret.append((port_rec, port_ips))

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

        # Init object
        self._docker = client
        self.storeMgr = parent.storeMgr
        self._tables = parent.conf["tables"]
        log("Working with tables: %s" % self._tables)
        self._domain = parent.conf["domain"].lstrip(".")
        self._default_ip = parent.conf["expose_ip"]

    def start(self):
        "Listen docker events"

        # Start the event poller, but don't read from the stream yet
        events = self._docker.events()

        # Bootstrap by inspecting all running containers
        for container in self._docker.containers():
            cont = ContainerInspect(
                self.storeMgr, self._docker.inspect_container(container["Id"])
            )

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
            # try:
            changed = True
            cont = ContainerInspect(self.storeMgr, self._docker.inspect_container(cid))
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
            old_records = self.storeMgr.query(self._tables, owner=cid, aggregate=True)
            with self.storeMgr.session(self._tables) as store:
                for store_name, records in old_records.items():
                    for rec in records:
                        store.remove([store_name], rec)
        if changed:
            log("Dump table content changes: %s" % status)
            self.storeMgr.debug()
