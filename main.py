from server import run_server
import configuration.configwriter as configwriter
import configuration.configreader as configreader

if __name__ == '__main__':
   configwriter.create_config_file()
   config = configreader.read_config_file()   
   run_server(config)