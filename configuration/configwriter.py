import configparser

import utils.constants as constants

"""
    Function to write configuraation file
    Parameters:
    Returns:
"""
def create_config_file():
    config = configparser.ConfigParser(strict=False)
    config["SERVER"] = {}
    config["SERVER"]["ip_addr"] = "0.0.0.0" 
    config["SERVER"]["port"] = "80"
    config["SERVER"]["connections"] = "4"
    config["SERVER"]["timeout"] = "5"

    config["MAPPING"] = {}
    config["MAPPING"]["root_dir"] = "/var/www"
    config["MAPPING"]["host_path"] = "http://cs531-cs_ptoma001"
    config["MAPPING"]["default_authorization_file"] = "WeMustProtectThisHouse!"
    config["MAPPING"]["private_key"] = "ptomar"

    config["HEADERS"] = {} 
    config["HEADERS"]["http_methods"] = "GET,HEAD,OPTIONS,TRACE"
    config["HEADERS"]["http_version"] = "1.1"
    config["HEADERS"]["server"] = "cs_ptoma001_server"
    config["MAPPING"]["access_log"] =  "/.well-known/access.log"
    config["MAPPING"]["log_file"] =  "access.log"
    config["HEADERS"]["mime_types"] = "text/plain,text/html,text/xml,image/png,image/jpeg,"\
                                        "image/gif,application/pdf,application/vnd.ms-powerpoint,"\
                                        "application/vnd.ms-word,message/http,application/octet-stream" 
    config["STATUS_CODE"] = {}
    config["STATUS_CODE"]["200"] = "OK"
    config["STATUS_CODE"]["206"] = "Partial Content"
    config["STATUS_CODE"]["300"] = "Multiple Choice"
    config["STATUS_CODE"]["301"] = "Moved Permanently"
    config["STATUS_CODE"]["302"] = "Found"
    config["STATUS_CODE"]["304"] = "Not Modified"
    config["STATUS_CODE"]["400"] = "Bad Request"
    config["STATUS_CODE"]["403"] = "Forbidden"
    config["STATUS_CODE"]["404"] = "Not Found"
    config["STATUS_CODE"]["406"] = "Not Acceptable"
    config["STATUS_CODE"]["408"] = "Request Timeout"
    config["STATUS_CODE"]["412"] = "Precondition Failed"
    config["STATUS_CODE"]["416"] = "Requested Range Not Satisfiable"
    config["STATUS_CODE"]["500"] = "Internal Server Error"
    config["STATUS_CODE"]["501"] = "Not Implemented"
    config["STATUS_CODE"]["505"] = "HTTP Version Not Supported"
    config["STATUS_CODE"]["401"] = "Unauthorized"

    config["REDIRECT"] = {}
    config["REDIRECT"]["302"] = "^(.*)/coolcar.html$ $1/galaxie.html, ^/a2-test/(.*)/1\.[234]/(.*) /a2-test/$1/1.1/$2"
    config["REDIRECT"]["301"] = "^(.*)/mercury/(.*)$ $1/ford/$2"

    config["ACCEPT_ENCODING"] = {}
    config["ACCEPT_ENCODING"]["x-compress"] = "compress"
    config["ACCEPT_ENCODING"]["x-gzip"] = "gzip"

    config["CHARSET_ENCODING"] = {}
    config["CHARSET_ENCODING"]["jis"] = "iso-2022-jp"
    config["CHARSET_ENCODING"]["koi8-r"] = "koi8-r"
    config["CHARSET_ENCODING"]["euc-kr"] = "euc-kr"

    config["CONTENT_ENCODING"] = {}
    config["CONTENT_ENCODING"]["gz"] = "gzip"
    config["CONTENT_ENCODING"]["z"] = "compress"
    config["CONTENT_ENCODING"]["zip"] = "x-zip"

    config["LANGUAGE_ENCODING"] = {}
    config["LANGUAGE_ENCODING"]["en"] = "en"
    config["LANGUAGE_ENCODING"]["es"] = "es"
    config["LANGUAGE_ENCODING"]["de"] = "de"
    config["LANGUAGE_ENCODING"]["ja"] = "ja"
    config["LANGUAGE_ENCODING"]["ko"] = "ko"
    config["LANGUAGE_ENCODING"]["ru"] = "ru"


    config["CREDENTIALS"] = {}
    config["CREDENTIALS"]["mln"] = "d3b07384d113edec49eaa6238ad5ff00"
    config["CREDENTIALS"]["bda"] = "c157a79031e1c40f85931829bc5fc552"
    config["CREDENTIALS"]["jbollen"] = "66e0459d0abbc8cd8bd9a88cd226a9b2"


    config["AUTHORIZATION"] = {}
    config["AUTHORIZATION"]["authorization-type"] = "Basic"
    config["AUTHORIZATION"]["realm"] = "Lane Stadium"


    with open(constants.CONFIG, "w") as fobj:
        config.write(fobj)