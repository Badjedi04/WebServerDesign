from configparser import ConfigParser
from collections import OrderedDict


class RedirectParser:

    def __init__(self, config_file):
        self.config = ConfigParser(dict_type=MultiOrderedDict, strict=False)
        self.config.read(config_file)
        self.temporary_redirect = self.config["Redirect"]["302"]
        self.permanent = self.config["Redirect"]["301"]
        self.logs_redirect = self.config["VirtualURI"][".well-known"]
        self.virtual_uri = self.config["VirtualURI"]


class MultiOrderedDict(OrderedDict):
    def __setitem__(self, key, value):
        if isinstance(value, list) and key in self:
            self[key].extend(value)
        else:
            super(MultiOrderedDict, self).__setitem__(key, value)

