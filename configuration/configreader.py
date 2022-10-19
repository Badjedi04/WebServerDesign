import sys
import configparser
from collections import OrderedDict

import utils.constants as constants

def read_config_file():
    try:
        dict_config = {}
        config = configparser.ConfigParser()
        config.read(constants.CONFIG)

        for section in config.sections():
            sys.stdout.write(f'section: {section}\n')
            dict_config[section] = {}
            for (key, value) in config[section].items():
                sys.stdout.write(f'key: {key}  value: {value}\n')
                dict_config[section][key] = convert_to_int(value)
        return dict_config
    except Exception as e:
        sys.stderr.write(f'read_config_file: error: {e}\n')

def convert_to_int(value):
    try:
        return int(value)
    except Exception as e:
        return convert_list(value)

def convert_list(value):
    if "," in value:
        splitter= value.split(",")
        return splitter
    else:
        return value    

"""
Function to read redirect.ini
"""
def read_redirect():
    try:
        config = configparser.ConfigParser()
        config.read("redirect.ini")
        config_dict = {}
        for section in config.sections(): 
            for (key, value) in config[section].items():
                if key in config:
                    if not isinstance(config[key], list):
                        temp = [config_dict[key], value]
                        config_dict.update({key:temp})
                    else:
                        config_dict[key].append(value)
                else:
                    config_dict[key] = value
        sys.stdout.write(f'read_redirect: \n{config_dict}\n')
        return config_dict
    except Exception as e:
        sys.stderr.write(f'read_redirect: error: {e}\n')

