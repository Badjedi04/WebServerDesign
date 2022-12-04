import configparser
import os


class MimeTypeReader:

    def __init__(self, config_file):
        self.config = configparser.ConfigParser()
        self.config.read(config_file)

    def check_mime_type(self, root_folder, file_requested):
        if os.path.isfile(root_folder + "/" + file_requested):
            file_extention = file_requested.rsplit(".", 1)[-1]
            try:
                return self.config['MIME_TYPES'][file_extention.lower()]
            except KeyError:
                return self.config['DEFAULT']['default']
