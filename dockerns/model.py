"Daens Core components"

# Imports
import importlib
import gevent
import signal
import sys

from pprint import pprint

# Import local libs
from dockerns.common import log


# BackendMangement
# ==================


class PluginInst:
    "Plugin Instance"

    default_conf = {
        "store": "default",
    }

    # Do not create if no name
    store_table_name = ""

    def __init__(self, parent, storeMgr, conf=None):
        "Default init signature"

        # Init object
        self.parent = parent
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

    def __init__(self, parent, stores, confs=None, settings=None):
        self.parent = parent
        self.stores = stores
        self.confs = confs or self.confs
        self.settings = settings or {}

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
            plugin = mod.Plugin(self, self.stores, conf=_conf)

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
