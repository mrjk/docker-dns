#!/usr/bin/env python


# dockerdns - simple, automatic, self-contained dns server for docker


# python 3 compatibility

# core
import os
from pprint import pprint

# from gevent import monkey
import urllib3

# Import local libs
from dockerns.common import log, read_file, from_json, to_json, write_file

# monkey.patch_all()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Record
# ==================


class Record:
    """Class for keeping track of a DNS record"""

    default_conf = {
        "domain": "",
        "name": "",
        "kind": "A",
        "rr": None,  # list
        "reverse": True,
        "owner": None,
        "meta": None,  # dict
    }

    def serialize(self):
        ret = self.__dict__
        return ret

    def __repr__(self):
        return f"Record({self.name}.{self.domain}:{self.kind})"

    def __init__(self, **kwargs):
        conf = dict(self.default_conf)
        conf.update(kwargs)
        for key, value in conf.items():
            setattr(self, key, value)

        self.rr = self.rr or []
        self.meta = self.meta or {}

        assert self.domain, f"Invalid domain '{self.domain}' for: {self.__dict__}"
        assert self.kind, f"Invalid kind '{self.kind}' for: {self.__dict__}"


# StateManagement
# ==================


class StoreTable:
    "Generic store table"

    def __init__(self, conf=None, name=None):
        "Default init signature"

        # Init object
        conf = dict(self.default_conf)
        conf.update(conf or {})
        self.conf = conf
        self.name = name or "default"

        self._db = []
        self._init()

    def _init(self):
        "Default init hook"

    def debug(self):
        "Debug hook"
        return self._db

    #    # CRUD methods
    def query(self, name=None, domain=None, owner=None, record=None):
        "Get hook"
        return None

    #
    #    def add(self, rec):
    #        "Add hook"
    #
    #    def rename(self, domain, old_name, new_name):
    #        "Rename hook"
    #
    #    def remove(self, rec):
    #        "Remove hook"
    #
    #
    #    # Serialization methods
    #    def serialize(self):
    #        "Serialize data"
    #
    #    def deserialize(self, payload):
    #        "Deserialize data"
    #
    # Commit methods
    def commit(self):
        "Commit hook"

    def prepare(self):
        "Prepare hook"


# Internal Tables
# ==================


class Stateful(StoreTable):
    "Stateful store table"

    default_conf = {
        "directory": "/tmp/dockerns",
    }

    def _init(self):
        # Load state DB from json file
        self.file = os.path.join(self.conf.get("directory"), self.name + ".json")

        if False:
            self._read_file()

    # Load from file
    # ----------------
    def _read_file(self):
        try:
            data = read_file(self.file)
            log(f"Read store state from: {self.file}")
        except FileNotFoundError:
            log(f"Ignore empty state file: {self.file}")
            data = ""

        if data:
            data = from_json(data) or []
        else:
            data = []

        self.deserialize(data)

    # Serialization
    # ----------------

    def commit(self):
        log(f"Save state in {self.file}")
        write_file(self.file, to_json(self.serialize()))

    def serialize(self):
        ret = []
        for rec in self._db:
            ret.append(rec.serialize())
        return ret

    def deserialize(self, payload):
        assert isinstance(payload, list)
        ret = []
        for rec in payload:
            ret.append(Record(**rec))
        self._db = ret

    # Table API - Queries
    # ----------------

    def get_record(self, record):
        "Get exact record"
        ret = []
        for rec in self._db:
            if rec == record:
                ret.append(rec)

        return ret

    def query(self, name=None, domain=None, owner=None, record=None):
        "Get hook"

        matches = []
        if record:
            matches = self.get_record(record)
        else:
            matches = self._db

        # Limit results
        filters = {
            "name": name,
            "owner": owner,
            "domain": domain,
        }
        for key, val in filters.items():
            if val is not None:
                matches = [rec for rec in matches if getattr(rec, key) == val]

        return matches

    # Table API - CRUD
    # ----------------

    def add(self, record):
        "Add hook"
        self._db.append(record)
        # self.commit()

    def rename(self, domain, old_name, new_name):
        "Rename hook"
        assert False, "Rename is not implemented"

    def remove(self, record):
        "Remove hook"
        self._db = [rec for rec in self._db if rec != record]
        # self.commit()


### NEW FILE: stores.py

# StoreManagement
# ==================


class StoreInst:
    "Single StoreInst"

    def __init__(self, name, conf=None, settings=None):
        self.settings = settings or {}
        self._tables = {}
        self.name = name
        self.conf = conf or {}

        if self.settings.stateful:
            self.add_table("stateful", Stateful(name))

    def add_table(self, name, value):
        self._tables[name] = value
        return self._tables[name]

    # Proxy functions
    # ---------------

    def _proxy_tables(self, method, *args, tables=None, **kwargs):
        tables = tables or list(self._tables.keys())
        for table_name, table in self._tables.items():
            if not table or table_name in tables:
                func = getattr(table, method)

                if func:
                    # print ("PROXY TABLE", method, table_name, args, kwargs)
                    func(*args, **kwargs)
                else:
                    print("FAILED PROXY TABLE", method, table_name, args, kwargs)
                    assert False

    def prepare(self):
        "prepare hook"
        self._proxy_tables("prepare")

    def commit(self):
        "commit hook"
        self._proxy_tables("commit")

    def add(self, *args):
        self._proxy_tables("add", *args)

    def rename(self, *args):
        self._proxy_tables("rename", *args)

    def remove(self, *args):
        self._proxy_tables("remove", *args)

    def query(self, *args, aggregate=False, **kwargs):
        if aggregate:
            ret = []
            for table_name, table in self._tables.items():
                rec = table.query(*args, **kwargs)
                if rec and rec not in ret:
                    ret.extend(rec)
        else:
            ret = {}
            for table_name, table in self._tables.items():
                ret[table_name] = table.query(*args, **kwargs)
        return ret

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

    def __init__(self, confs=None, settings=None):
        self.tables_conf = confs or dict(self.confs)
        self.settings = settings or {}
        self._stores = {
            name: StoreInst(name, conf, settings=self.settings)
            for name, conf in self.tables_conf.items()
        }

    def _filter_stores(self, store_names):
        # TOFIX: Yield this please
        assert isinstance(store_names, list)
        ret = {}
        for table_name in store_names:
            table = self._stores.get(table_name, None)
            if not table:
                continue
            ret[table_name] = table
        return ret.items()

    # Proxy functions
    # ---------------
    def _proxy_stores(self, method, store_names, *args, **kwargs):
        for store_name, store in self._filter_stores(store_names):
            func = getattr(store, method)
            if func:
                # print ("PROXY STORE", method, store_names, args, kwargs)
                func(*args, **kwargs)
            else:
                print("FAILED PROXY STORE", method, store_names, args, kwargs)
                assert False

    def add(self, store_names, *args, **kwargs):
        self._proxy_stores("add", store_names, *args, **kwargs)

    def rename(self, store_names, *args, **kwargs):
        self._proxy_stores("rename", store_names, *args, **kwargs)

    def remove(self, store_names, *args, **kwargs):
        self._proxy_stores("remove", store_names, *args, **kwargs)

    def query(self, store_names, *args, **kwargs):
        ret = {}
        for table_name, table in self._filter_stores(store_names):
            ret[table_name] = table.query(*args, **kwargs)
        return ret

    # Helpers
    # ---------------
    def ensure(self, name):
        if name not in self._stores:
            self._stores[name] = StoreInst(name, {}, settings=self.settings)
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

    def session(self, store_names):
        "Return session context"

        class Session:
            def __init__(self, mgr, store_names):
                self.mgr = mgr
                self.store_names = store_names

            def __enter__(self):
                self.mgr._proxy_stores("prepare", self.store_names)
                return self.mgr

            def __exit__(self, exc_type, exc_val, exc_tb):
                self.mgr._proxy_stores("commit", self.store_names)

        return Session(self, store_names)
