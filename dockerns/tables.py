#!/usr/bin/env python


# dockerdns - simple, automatic, self-contained dns server for docker


# python 3 compatibility

# core

from pprint import pprint

# from gevent import monkey
import urllib3
import importlib
import gevent

# Import local libs
from dockerns.common import log

# monkey.patch_all()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# StoreManagement
# ==================


class StoreInst:
    "Single StoreInst"

    def __init__(self, name, conf=None):
        self._tables = {}
        self.name = name
        self.conf = conf or {}

    def add_table(self, name, value):
        self._tables[name] = value
        return self._tables[name]

    # Proxy functions
    # ---------------
    def add(self, domain, name, address):
        for table_name, table in self._tables.items():
            table.add(domain, name, address)

    def rename(self, domain, old_name, new_name):
        for table_name, table in self._tables.items():
            table.rename(domain, old_name, new_name)

    def remove(self, domain, name):
        for table_name, table in self._tables.items():
            table.remove(domain, name)

    def get(self, domain, name, aggregate=False):
        ret = {}
        for table_name, table in self._tables.items():
            ret[table_name] = table.get(name, domain=domain)
        return ret

    def remove_ip(self, domain, ip, arp=True):
        for table_name, table in self._tables.items():
            table.remove_ip(ip)
            # if arp:
            #    rev_ip =
            #    table.remove_ip(ip)

    # Other
    # ---------------

    def debug(self):
        ret = {
            "obj": self.__dict__,
            "records": {
                key: val.debug() or "<NO RECORDS>" for key, val in self._tables.items()
            },
            #'_tables': { key: val.debug() for key, val in self._tables.items() },
        }
        return ret or "<NO RECORDS>"


class StoreMgr:
    "StoreMgr"

    confs = {"default": {}}

    def __init__(self, confs=None):
        self.tables_conf = confs or dict(self.confs)
        self._stores = {
            name: StoreInst(name, conf) for name, conf in self.tables_conf.items()
        }

    def _filter_stores(self, tables):
        # TOFIX: Yield this please
        ret = {}
        for table_name in tables:
            table = self._stores.get(table_name, None)
            if not table:
                continue
            ret[table_name] = table
        return ret.items()

    # Proxy functions
    # ---------------
    def add(self, tables, domain, name, address):
        for table_name, table in self._filter_stores(tables):
            table.add(domain, name, address)

    def rename(self, tables, domain, name, new_name):
        for table_name, table in self._filter_stores(tables):
            table.rename(domain, name, new_name)

    def remove(self, tables, domain, name):
        for table_name, table in self._filter_stores(tables):
            table.remove(domain, name)

    def remove_ip(self, tables, domain, name):
        for table_name, table in self._filter_stores(tables):
            table.remove_ip(domain, name)

    def get(self, tables, domain, name):
        ret = {}
        for table_name, table in self._filter_stores(tables):
            ret[table_name] = table.get(domain, name)
        return ret

    # Helpers
    # ---------------
    def ensure(self, name):
        if name not in self._stores:
            self._stores[name] = StoreInst(name, {})
        return self._stores[name]

    def get_table(self, name):
        return self._stores[name]._table

    def debug(self):
        print("Store table debug:")
        ret = {}
        for table_name, table in self._stores.items():
            ret[table_name] = table.debug()

        pprint(ret, indent=2)
        return ret


# BackendMangement
# ==================


class PluginInst:
    "Plugin Instance"

    default_conf = {
        "store": "default",
    }

    # Do not create if no name
    store_table_name = ""

    def __init__(self, storeMgr, conf=None):
        "Default init signature"

        # Init object
        self.storeMgr = storeMgr
        conf = dict(self.default_conf)
        conf.update(conf or {})
        self.conf = conf

        # Pre init
        self._store = None
        self.store_name = None
        self._table = None

        # Init store
        sname = self.conf.get("store", "default")
        self.store_name = sname

        tname = self.store_table_name
        if tname:
            # Fetch store name
            store = self.storeMgr.ensure(sname)
            # Add plugins backend table
            table = store.add_table(tname, self.init_store())

            self._store = store
            self._table = table

    def start_svc(self):
        "Start hook (TOFIX: Name), MUST RETURN A FUNCTION"

        def func():
            print("My one shot plugin")

        return func

    def init_store(self):
        "Default store"
        return {}


class PluginMgr:
    "Plugin Manager"

    confs = {}
    module_prefix = "dockerns."

    def __init__(self, stores, confs=None):
        self.stores = stores
        self.confs = confs or self.confs

        self._proclist = None
        self._children = None

        self._init()

    def _init(self):
        "Allow local override hook"
        pass

    def start(self):
        "Init and start pluging background process"
        assert self._children is None

        self._children = {}
        proclist = []
        for backend_name, _conf in self.confs.items():
            # Get config
            driver = _conf.get("driver", None)
            # store_name = _conf.get("store", "default")
            if not driver:
                continue

            # Load python module
            pkg_name = f"{self.module_prefix}{driver}"
            mod = importlib.import_module(pkg_name)

            # Create plugin instance
            log("Loading plugin: %s" % pkg_name)
            plugin = mod.Plugin(self.stores, conf=_conf)

            # Start background process, must return a function/callable, or skipped
            func = plugin.start_svc()
            if callable(func):
                proc = gevent.spawn(func)
                proclist.append(proc)

            self._children[backend_name] = plugin

        self._proclist = proclist
        return proclist


# Overrides
# ==================


class BackendInst(PluginInst):
    "Backend Instance"


class BackendMgr(PluginMgr):
    "Backend Manager"

    module_prefix = "dockerns.output."


class SourceInst(PluginInst):
    "Source Instance"


class SourceMgr(PluginMgr):
    "Source Manager"

    module_prefix = "dockerns.source."
