import sys
import configparser

import utils.constants as constants

def read_config_file():
    try:
        dict_config = {}
        config = configparser.ConfigParser()
        config.read(constants.CONFIG)

        for section in config.sections():
            #sys.stdout.write(f'section: {section}\n')
            dict_config[section] = {}
            for (key, value) in config[section].items():
                #sys.stdout.write(f'key: {key}  value: {value}\n')
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
        return convert_to_bool(value)    

def convert_to_bool(value):
    if value == "True":
        return True
    elif value == "False":
        return False
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
            #sys.stdout.write(f'read_redirect: section: {section}\n')
            for (key, value) in config[section].items():
                #sys.stdout.write(f'read_redirect: {key}: {value}\n')
          
                config_dict[key] = convert_list(value)
                #sys.stdout.write(f'read_redirect: \n{config_dict}\n')
        
        #sys.stdout.write(f'read_redirect: Final: \n{config_dict}\n')
        return config
    except Exception as e:
        sys.stderr.write(f'read_redirect: error: {e}\n')


def read_accept_encoding_config_file():
    try:
        dict_config = {}
        config = configparser.ConfigParser()
        config.read("acceptencoding.ini")
        for section in config.sections(): 
            #sys.stdout.write(f'read_accept_encoding_config_file: section: {section}\n')
            for (key, value) in config[section].items():
                #sys.stdout.write(f'read_accept_encoding_config_file: {key}: {value}\n')
                dict_config[key] = value
        return dict_config
    except Exception as e:
        sys.stderr.write(f'read_accept_encoding_config_file: error: {e}\n')


def read_charset_encoding_config_file():
    try:
        dict_config = {}
        config = configparser.ConfigParser()
        config.read("charsetencoding.ini")
        for section in config.sections(): 
            #sys.stdout.write(f'read_charset_encoding_config_file: section: {section}\n')
            for (key, value) in config[section].items():
                #sys.stdout.write(f'read_charset_encoding_config_file: {key}: {value}\n')
                dict_config[key] = value
        return dict_config
    except Exception as e:
        sys.stderr.write(f'read_charset_encoding_config_file: error: {e}\n')


def read_content_encoding_config_file():
    try:
        dict_config = {}
        config = configparser.ConfigParser()
        config.read("contentencoding.ini")
        for section in config.sections(): 
            #sys.stdout.write(f'read_content_encoding_config_file: section: {section}\n')
            for (key, value) in config[section].items():
                #sys.stdout.write(f'read_content_encoding_config_file: {key}: {value}\n')
                dict_config[key] = value
        return dict_config
    except Exception as e:
        sys.stderr.write(f'read_content_encoding_config_file: error: {e}\n')


def read_lang_encoding_config_file():
    try:
        dict_config = {}
        config = configparser.ConfigParser()
        config.read("langencoding.ini")
        for section in config.sections(): 
            #sys.stdout.write(f'read_lang_encoding_config_file: section: {section}\n')
            for (key, value) in config[section].items():
                #sys.stdout.write(f'read_lang_encoding_config_file: {key}: {value}\n')
                dict_config[key] = value
        return dict_config
    except Exception as e:
        sys.stderr.write(f'read_lang_encoding_config_file: error: {e}\n')
