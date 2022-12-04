import configparser


class MimeTypeReader:

    def __init__(self, config_file):
        self.config = configparser.ConfigParser()
        self.config.read(config_file)

    def check_mime_type(self, extension):
        try:
            return self.config['MIME_TYPES'][extension.lower()]
        except KeyError:
            return self.config['DEFAULT']['default']
