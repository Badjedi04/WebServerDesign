import configparser
import constants

def read_config_file():
    config = configparser.ConfigParser()
    config.read(constants.CONFIG)
    for (key, value) in config.items():
        config[key] = convert_to_int(value)
    return config

def convert_to_int(value):
    try:
        return int(value)
    except ValueError:
        return convert_list(value)

def convert_list(value):
    if "," in value:
        splitter= value.split(",")
        return splitter
    else:
        return value    

