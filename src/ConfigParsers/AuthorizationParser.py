import configparser


class AuthorizationParser:

    def __init__(self, config_file):
        self.config = configparser.ConfigParser()
        self.config.read(config_file)

    def get_authorization_type(self, key):
        try:
            return self.config['AUTHORIZATION'][key.lower()]
        except KeyError:
            return None

    def get_credentials(self, user):
        try:
            return self.config['CREDENTIALS'][user.lower()]
        except KeyError:
            return None
