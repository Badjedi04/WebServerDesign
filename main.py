import Config.configwriter as configwriter
import Config.configreader as configreader

if __name__ == '__main__':
   configwriter.create_config_file()
   config = configreader.read_config_file()   
