import configparser


class AcceptEncodingParser:

    def __init__(self, config_file):
        self.config = configparser.ConfigParser()
        self.config.read(config_file)

    def check_accept_encoding_type(self, file_extension):
        try:
            return self.config['accept_encoding'][file_extension.lower()]
        except KeyError:
            return None
