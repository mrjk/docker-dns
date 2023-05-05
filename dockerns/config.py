import os
import anyconfig
import argparse
from pprint import pprint

RUNTIME_CONF = {
        "file_config": None,
        "log_level": "info",
        "verbose": True,
        "stateful": True,
    }

DEFAULT_CONF = {
    "vars": {
        "my_var1": "domain.org",
        "expose_ip": "12.12.12.15",
    },
    #"config": RUNTIME_CONF, # DEPRECATED
    "runtime": RUNTIME_CONF,
    "outputs": {
        "default": {
            "driver": "embedded",
            "bind": "0.0.0.0:53",
            "resolvers": "8.8.8.8,8.8.4.4",
            "recurse": True,
            "records": ["default"],
            "store": "default",
        },
    },
    "sources": {
        "default": {
            "driver": "cont_base",
            "stores": ["default"],
            "docker": "unix:///var/run/docker.sock",
            "expose_ip": "12.12.12.15",  # DEPRECATED
            "domain": "docker",  # DEPRECATED
            #'records': {
            #    'default': {
            #            'tld': 'docker',
            #            #'tld': 'example.org',
            #            'cont_template': 'JINJA_STR',
            #        },
            #    },
            # },
        },
        # "tables": {
        #    "default": {
        #        "tld": "docker",
        #        "cont_template": "JINJA_STR",
        #        # NOLOGIC HERE ! 'reverse': True,
        #        # NOLOGIC HERE ! 'parse_labels': True,
        #    },
        # },
        # "other": {
        #    "tld": "docker",
        #    #'tld': 'example.org',
        #    "cont_template": "JINJA_STR",
        # },
    },
}


class DockerNSConfig:
    runtime_conf = RUNTIME_CONF
    default_conf = DEFAULT_CONF

    def __init__(self):
        #conf = self.conf_from_defaults()
        ## conf.update(self.conf_from_file())
        ## conf.update(self.conf_from_env())
        #conf["config"].update(self.conf_from_cli())


        # Load runtime configuration
        # -------------------
        rt_default = dict(self.runtime_conf)
        rt_cli = self.conf_from_cli()

        rt_conf = {}
        rt_conf.update(rt_default)
        rt_conf.update(rt_cli)
        #self.rt_conf = rt_conf

        user_conf = {
                    "runtime": rt_conf,
                }

        #pprint (rt_conf)


        # Load user configuration
        # -------------------
        config_files = rt_conf['file_config'] or []
        if isinstance(config_files, str):
            config_files = config_files.split(',')
        if not isinstance(config_files, list):
            config_files = [config_files]

        if config_files:
            ac_conf = anyconfig.load(config_files, ac_parser="yaml")
        else:
            ac_conf = self.default_conf

        user_conf.update(ac_conf)

        self._conf = user_conf
        return
        #pprint (user_conf)

        #assert False

        #cli_default = self.conf_from_defaults()
        #cli_config = { 'config': self.conf_from_cli() }

        #dump = {
        #        "cli_default": cli_default,
        #        "cli_config": cli_config

        #        }

        #self._conf = {}
        #self._conf.update(cli_default)
        #self._conf.update(cli_config)

        #print ("SPLIT")
        #pprint (dump)
        #print ("MERGED")
        #pprint (self._conf)

    def _conf_opts(self):
        "Return a key value config for app"
        ret = self.conf_from_defaults().get("runtime")
        return ret

    # Config sources
    # ==========================

    def conf_from_defaults(self):
        return dict(DEFAULT_CONF)

    def conf_from_file(self):
        return {}

    def conf_from_env(self):
        ret = {}
        for key, value in os.environ.items():
            if key.startswith("DOCKERNS_"):
                ret[key] = value
        return {}

    def conf_from_cli(self):
        PROCESS = "dockerns"
        EPILOG = "dockerns epilog"

        parser = argparse.ArgumentParser(
            PROCESS,
            epilog=EPILOG,
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        )

        #       parser.add_argument('--config', default=DOCKERNS_CONFIG,
        #                           help='dockerns yaml configuration')

        for key, value in self._conf_opts().items():
            opt_name = "--%s" % key.replace("_", "-")
            var_name = "DOCKERNS_%s" % key.upper()
            default_val = os.environ.get(var_name, value)
            parser.add_argument(opt_name, default=default_val, help=f"NOHELP [{var_name}]")

        ret = dict(parser.parse_args().__dict__)
        return ret

    # Assemble configs
    # ==========================

    def get_conf(self, pattern, conf=None, default=None):
        "Return a key config"

        _conf = conf or self._conf
        for part in pattern.split("."):
            if isinstance(_conf, dict):
                _conf = _conf.get(part, None)
        return _conf or default

    def init_conf(self):
        conf_default = self.conf_from_defaults()

        conf_cli = self.conf_from_cli()
        #conf_env = self.conf_from_env()
        conf_file = self.conf_from_file()

        confs = [conf_default, conf_file, conf_env, conf_cli]

        # anyconfig.merge (self, other, ac_merge=MS_DICTS, **options)

        ret = {}
        for conf in confs:
            ret.update()

        # Config precedence
        # cli > envvars > config_file > defaults

        # Read file config
        #

    def load_file(self, file):
        "Load configuration from file"

        self._file_path = file
        anyconfig.load(file, ac_parser="yaml")
