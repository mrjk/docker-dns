
import anyconfig
import argparse
from pprint import pprint


DEFAULT_CONF = {
    'vars': {
            'my_var1': 'domain.org',
            'expose_ip': '12.12.12.15',
        },
    'config': {
        'file_config': 'config.yml',
        'log_level': 'debug',
        },
    'sources': {
        'cont': {
            'driver': 'cont_base',
            'tables': ['default'],
            'docker': 'unix:///var/run/docker.sock',
            'expose_ip': '12.12.12.15', # DEPRECATED
            #'records': {
            #    'default': {
            #            'tld': 'docker',
            #            #'tld': 'example.org',
            #            'cont_template': 'JINJA_STR',
            #        },
            #    },
            #},
        },
    'tables': {
        'default': {
                'tld': 'docker',
                'cont_template': 'JINJA_STR',
                # NOLOGIC HERE ! 'reverse': True,
                # NOLOGIC HERE ! 'parse_labels': True,
            },
        },
        'other': {
                'tld': 'docker',
                #'tld': 'example.org',
                'cont_template': 'JINJA_STR',
            },
        },
    'outputs': {
        'embedded': {
                'driver': 'embedded',
                'bind': '127.0.0.1:5358',
                'resolvers': '8.8.8.8,8.8.4.4',
                'recurse': True,
                'records': ['default'],
                'table': 'default',
            },
        },
    }


class DockerNSConfig():

    default_conf = DEFAULT_CONF

    def __init__(self):
        conf = self.conf_from_defaults()
        #conf.update(self.conf_from_file())
        #conf.update(self.conf_from_env())
        conf['config'].update(self.conf_from_cli())

        self._conf = conf

    def _conf_opts(self):
        "Return a key value config for app"
        ret = self.conf_from_defaults().get('config')
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
            if key.startswith('DOCKERNS_'):
                ret[key] = value
        return {}

    def conf_from_cli(self):
        PROCESS = 'dockerns'
        EPILOG = 'dockerns epilog'

        parser = argparse.ArgumentParser(PROCESS, epilog=EPILOG,
                formatter_class=argparse.ArgumentDefaultsHelpFormatter)

 #       parser.add_argument('--config', default=DOCKERNS_CONFIG,
 #                           help='dockerns yaml configuration')

        for key, value in self._conf_opts().items():
            opt_name = "--%s" % key.replace('_', '-')
            parser.add_argument(opt_name, default=value,
                                help='NOHELP')


        ret = dict(parser.parse_args().__dict__)
        pprint (ret)
        return ret

    # Assemble configs
    # ==========================

    def get_conf(self, pattern, conf=None):
        "Return a key config"

        _conf = conf or self._conf
        for part in pattern.split('.'):
            if isinstance(_conf, dict):
                _conf = _conf.get(part, None)
        return _conf


    def init_conf(self):

        conf_default = self.conf_from_defaults()

        conf_cli = self.conf_from_cli()
        conf_env = self.conf_from_env()
        conf_file = self.conf_from_file()

        
        confs = [conf_default, conf_file, conf_env, conf_cli]

        #anyconfig.merge (self, other, ac_merge=MS_DICTS, **options)

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



