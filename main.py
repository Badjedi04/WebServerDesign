from echoserver import start_server
from Configuration.configwriter import write_config
from Configuration.configreader import config_file_reader

if __name__ == '__main__':
     write_config()
     config = config_file_reader()
     start_server(config)