import configparser


class ConfigReader:

    def __init__(self, config_file):
        self.config = configparser.ConfigParser()
        self.config.read(config_file)
        self.root_folder = self.config['COMMON']['ROOT_FOLDER']
        self.access_debugging_folder = self.config['COMMON']['ACCESS_LOG_FOLDER']
        self.debug_folder = self.config['COMMON']['DEBUGGING_LOG_FOLDER']
        self.default_port = self.config['AUTHOR']['DEFAULT_PORT']
        self.default_ip_addr = self.config['AUTHOR']['DEFAULT_IP']
        self.default_timeout = self.config['AUTHOR']['DEFAULT_TIMEOUT']
        self.server_name = self.config['AUTHOR']['SERVER_NAME']
        self.resolve_hostname = self.config['AUTHOR']['RESOLVE_IP_TO_HOSTNAME']
        self.error_folder = self.config['COMMON']['ERROR_FOLDER']
        self.http_version = self.config['AUTHOR']['HTTP_VERSION']