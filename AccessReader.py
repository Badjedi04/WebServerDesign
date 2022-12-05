import configparser


class AccessReader:

    def __init__(self, config_file):
        self.config = configparser.ConfigParser()
        self.config.read(config_file)
        self.restricted_files = self.config['RESTRICTED']['FILES']
        self.restricted_folders = self.config['RESTRICTED']['FOLDERS']
        self.access_files = self.config['ACCESS']['FILES']
        self.access_folders = self.config['ACCESS']['FOLDERS']
        self.logs_redirect = self.config["VirtualURI"][".well-known"]
        self.virtual_uri = self.config["VirtualURI"]
