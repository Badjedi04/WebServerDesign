import configparser
import os

import constants  


def write_config():
    if not os.path.exists(constants.CONFIG_DIR):
        os.mkdir(constants.CONFIG_DIR)
    config = configparser.ConfigParser()

    config['SERVER'] = {}
    config['SERVER']['ip_addr'] = "0.0.0.0"
    config['SERVER']['port'] = "80"
    config['SERVER']['max_conn'] = "3"
    config["SERVER"]["timeout"] = "5"

    config["MAPPING"] = {}
    config["MAPPING"]["root_dir"] = "/var/www"
    config["MAPPING"]["host_path"] = "http://cs531-cs_rchau004"

    config["HEADERS"] = {}
    config["HEADERS"]["http_methods"] = "GET,HEAD,OPTIONS,TRACE"
    config["HEADERS"]["http_version"] = "1.1"
    config["HEADERS"]["server"] = "cs_rchau004_server"
    config["HEADERS"]["mime_types"] = "text/plain,text/html,text/xml,image/png,image/jpeg,image/gif,"\
                                        "application/pdf,application/vnd.ms-powerpoint,"\
                                        "application/vnd.ms-word,message/http,application/octet-stream"

                                    
    config["STATUS_CODE"] = {}
    config["STATUS_CODE"]["200"] = "Ok"
    config["STATUS_CODE"]["301"] = "Moved Permanently"
    config["STATUS_CODE"]["302"] = "Found"
    config["STATUS_CODE"]["304"] = "Not Modified"
    config["STATUS_CODE"]["400"] = "Bad Response"
    config["STATUS_CODE"]["403"] = "Forbidden"
    config["STATUS_CODE"]["404"] = "Not Found"
    config["STATUS_CODE"]["408"] = "Request Timeout"
    config["STATUS_CODE"]["412"] = "Precondition Failed"
    config["STATUS_CODE"]["500"] = "Internal Server Error"
    config["STATUS_CODE"]["501"] = "Not IMplemented"
    config["STATUS_CODE"]["505"] = "HTTP Version Not Supported"
   
    config["REDIRECT"] = {}
    config["REDIRECT"]["302"] = "^(.*)/coolcar.html$ $1/galaxie.html, ^/a2-test/(.*)/1\.[234]/(.*) /a2-test/$1/1.1/$2"
    config["REDIRECT"]["301"] = "^(.*)/mercury/(.*)$ $1/ford/$2"

    with open(constants.CONFIG, 'w') as configfile:
      config.write(configfile)

