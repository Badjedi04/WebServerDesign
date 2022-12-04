import configparser


class ContentLanguageParser:

    def __init__(self, config_file):
        self.config = configparser.ConfigParser()
        self.config.read(config_file)

    def check_content_language(self, file_extension):
        try:
            return self.config['content_language'][file_extension.lower()]
        except KeyError:
            return None
