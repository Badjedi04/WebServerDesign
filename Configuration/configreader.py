import sys
import configparser
import constants

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
