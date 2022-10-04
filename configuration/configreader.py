import configparser
import constants

def read_config_file():
    config = configparser.ConfigParser()
    config.read(constants.CONFIG)
    for section in config.sections():
        for (key, value) in config[section].items():
            config[section][key] = convert_to_int(value)
    return config

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

