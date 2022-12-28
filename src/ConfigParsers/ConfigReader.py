import configparser
import os


class ConfigReader:

    def __init__(self, config_file):
        self.config = configparser.ConfigParser()
        self.config.read(config_file)
        self.root_folder = self.config['COMMON']['ROOT_FOLDER']
        if not os.path.isdir(self.root_folder + "/logs/"):
            os.mkdir(self.root_folder + "/logs/")
        self.access_debugging_folder = self.config['COMMON']['ACCESS_LOG_FOLDER']
        self.debug_folder = self.config['COMMON']['DEBUGGING_LOG_FOLDER']
        self.default_port = self.config['AUTHOR']['DEFAULT_PORT']
        self.default_ip_addr = self.config['AUTHOR']['DEFAULT_IP']
        self.default_timeout = self.config['AUTHOR']['DEFAULT_TIMEOUT']
        self.server_name = self.config['AUTHOR']['SERVER_NAME']
        self.resolve_hostname = self.config['AUTHOR']['RESOLVE_IP_TO_HOSTNAME']
        if not os.path.isdir(self.root_folder + "/error_page/"):
            os.mkdir(self.root_folder + "/error_page/")
        self.error_folder = self.config['COMMON']['ERROR_FOLDER']
        self.http_version = self.config['AUTHOR']['HTTP_VERSION']
        self.default_page = self.config['COMMON']['DEFAULT_PAGE']
        self.authorization_file = self.config['COMMON']['DEFAULT_AUTHORIZATION_FILE']
        self.private_key = self.config['COMMON']['PRIVATE_KEY']