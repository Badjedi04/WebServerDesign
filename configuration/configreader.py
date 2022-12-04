import sys
import configparser
import constants

def config_file_reader():
    try:
        dict_config = {}
        config = configparser.ConfigParser()
        config.read(constants.CONFIG)

        for section in config.sections():
            sys.stdout.write(f'section: {section}\n')
            dict_config[section] = {}
            for (key, value) in config[section].items():
                sys.stdout.write(f'key: {key}  value: {value}\n')
                dict_config[section][key] = translate_to_int(value)
        sys.stdout.write(f'config: \n{dict_config}\n')
        return dict_config
    except Exception as e:
        sys.stderr.write(f'config_file_reader: error: {e}\n')

def translate_to_int(value):
    try:
        return int(value)
    except Exception as e:
        return translate_list(value)

def translate_list(value):
    if "," in value:
        splitter= value.split(",")
        return splitter
    else:
        return value   


def redirect_reader():
    config = configparser.ConfigParser()
    config.read("redirect.ini")
    
    config_dict = {}
    for section in config.sections(): 
        sys.stdout.write(f'redirect_reader: section: {section}\n')
        for (key, value) in config[section].items():
            sys.stdout.write(f'redirect_reader: {key}: {value}\n')
          
            config_dict[key] = translate_list(value)
            sys.stdout.write(f'redirect_reader: \n{config_dict}\n')
        
    sys.stdout.write(f'redirect_reader: Final: \n{config_dict}\n')
    return config
    