import configparser
import constants

"""
    Function to write configuraation file
    Parameters:

    Returns:

"""
def create_config_file():
    config = configparser.ConfigParser()
    config["SERVER"] = {}
    config["SERVER"]["ip_addr"] = "0.0.0.0" 
    config["SERVER"]["port"] = "80"
    config["SERVER"]["connections"] = "50"

    config["MAPPING"] = {}
    config["MAPPING"]["root_dir"] = "/var/www"
    config["MAPPING"]["host_path"] = "http://cs531-cs_ptoma001"

    config["HEADERS"] = {} 
    config["HEADERS"]["http_methods"] = "GET,HEAD,OPTIONS,TRACE"
    config["HEADERS"]["http_version"] = "HTTP/1.1"
 
    with open(constants.CONFIG, "w") as fobj:
        config.write(fobj)


create_config_file()