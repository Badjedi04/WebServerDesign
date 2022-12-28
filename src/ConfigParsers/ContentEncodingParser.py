import configparser


class ContentEncodingParser:

    def __init__(self, config_file):
        self.config = configparser.ConfigParser()
        self.config.read(config_file)

    def check_encoding_type(self, file_extension):
        try:
            return self.config['content_encoding'][file_extension.lower()]
        except KeyError:
            return None

    def check_character_set_type(self, file_extension):
        try:
            return self.config['character_set_encoding'][file_extension.lower()]
        except KeyError:
            return None
