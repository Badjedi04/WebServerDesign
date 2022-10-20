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
        config = configparser.ConfigParser(dict_type= M, strict=False)
        config.read("redirect.ini")
        
        config_dict = {}
        sys.stdout.write(f'read_redirect: section: {section}\n')
        for section in config.sections(): 
            sys.stdout.write(f'read_redirect: section: {section}\n')
            for (key, value) in config[section].items():
                sys.stdout.write(f'read_redirect: {key}: {value}\n')
                value = value.replace("[", "").replace("]", "")
                if "," in value:
                    value = value.split(",")
                config_dict[key] = value
            sys.stdout.write(f'read_redirect: \n{config_dict}\n')
        
        #sys.stdout.write(f'read_redirect: Final: \n{config_dict}\n')
        return config
    except Exception as e:
        sys.stderr.write(f'read_redirect: error: {e}\n')
