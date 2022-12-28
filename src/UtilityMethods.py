import os
from datetime import datetime
from src.Constants import *
from src.AuthorizationStructure import AuthorizationStructure


'''
Check if function name is GET or HEAD
'''


def is_method_get_head(report):
    if report["request"]["method"] == "GET" or report["request"]["method"] == "HEAD":
        return True
    else:
        return False


'''
Check if status code is 200 or 206
'''


def if_status_code_200_class(report):
    if report["response"]["status_code"] == STATUS_OK or report["response"]["status_code"] == STATUS_PARTIAL_CONTENT:
        return True
    else:
        return False


'''
Check file last modified time
'''


def check_file_modified_time(report, config_instance):
    if report["response"]["content_location"] is not None:
        resource_location = report["response"]["content_location"]
    else:
        resource_location = report["request"]["path"]
    last_modified = os.path.getmtime(config_instance.root_folder + resource_location)
    last_modified = datetime.utcfromtimestamp(last_modified)
    last_modified = datetime.strftime(last_modified, "%a, %d %b %Y %H:%M:%S")
    return last_modified


'''
Function to check if extension is image
'''


def has_image_extension(extension):
    list_image_extensions = ["jpg", "jpeg", "gif", "png", "tiff"]
    if extension in list_image_extensions:
        return True
    else:
        return False


'''
Function to check extension has charset
'''


def has_charset_extension(extension):
    list_charset = ["iso-2022-jp", "koi8-r", "euc-kr"]
    if extension in list_charset:
        return True
    else:
        return False


'''
Function to check language extension
'''


def has_language_extension(extension):
    list_language = ["en", "es", "de", "ja", "ko", "ru"]
    if extension in list_language:
        return True
    else:
        return False


'''
Function to check encoding extension
'''


def has_encoding_extension(extension):
    list_encoding = ["Z", "gz"]
    if extension in list_encoding:
        return True
    else:
        return False


'''
Function to check if accept headers present
'''


def has_accept_headers(report):
    if report["request"]["accept_encoding"] is not None or report["request"]["accept_language"] is not None or \
            report["request"]["accept_charset"] is not None or report["request"]["accept"] is not None:
        return True
    else:
        return False


'''
Function to return sorted list of accept headers
'''


def sort_accept_headers(list_accept):
    list_temp = []
    list_accept_parameter = []
    for parameters in list_accept:
        list_temp.append(parameters.split(";")[-1].split("=")[-1])
        list_accept_parameter.append(parameters.lstrip())
    list_temp, list_accept = zip(*sorted(zip(list_temp, list_accept_parameter), reverse=True))
    return list_accept


'''
Function to check file extensions
'''


def check_file_extensions(resource, config_mime_type, config_content_encoding, config_content_language,
                          config_charset_parser):
    mime_type = None
    content_encoding_ext = None
    content_language_ext = None
    character_set_encoding_ext = None
    file_extensions = resource.split(FORWARD_SLASH)[-1].split(".")[1:]
    for index_extensions in range(0, len(file_extensions)):
        if mime_type is None or mime_type == "application/octet-stream":
            mime_type = config_mime_type.check_mime_type(file_extensions[index_extensions])
        if content_encoding_ext is None:
            content_encoding_ext = config_content_encoding.check_encoding_type(file_extensions[index_extensions])
        if content_language_ext is None:
            content_language_ext = config_content_language.check_content_language(file_extensions[index_extensions])
        if character_set_encoding_ext is None:
            character_set_encoding_ext = config_charset_parser.check_character_set_type\
                (file_extensions[index_extensions])
    if mime_type is None and len(file_extensions) == 0:
        mime_type = config_mime_type.check_mime_type("")
    return mime_type, content_encoding_ext, content_language_ext, character_set_encoding_ext


'''
Function to set alternatives header
'''


def set_alternatives_header(report, list_files, list_extensions, list_file_length):
    alternatives = ""
    for index_files in range(0, len(list_files)):
        alternatives += "{ \"" + list_files[index_files] + "\" 1 "
        for index_ext in range(0, len(list_extensions)):
            if list_extensions[index_ext][index_files] is not None:
                if index_ext == 0:
                    alternatives += "{type " + list_extensions[index_ext][index_files] + "}"
                elif index_ext == 1:
                    alternatives += "{charset " + list_extensions[index_ext][index_files] + "}"
                elif index_ext == 2:
                    alternatives += "{language " + list_extensions[index_ext][index_files] + "}"
                elif index_ext == 3:
                    alternatives += "{encoding " + list_extensions[index_ext][index_files] + "}"
        alternatives += "{length " + str(list_file_length[index_files]) + "}}"
    report["response"]["alternatives"] = alternatives
    return report


'''
Function to check htaccess 
'''


def check_authorization_directory(config_instance, path):
    authorization_info = None
    while authorization_info is None and path != config_instance.root_folder:
        if os.path.isdir(path):
            authorization_info = fill_authorization(config_instance,path)
        if authorization_info is None:
            path = path.rsplit(FORWARD_SLASH, 1)[0]
        else:
            return authorization_info
    return None


'''
Function to fill authorization file
'''


def fill_authorization(config_instance, path):
    authorization_info = AuthorizationStructure().report
    list_users = []
    for files in os.listdir(path):
        if files == config_instance.authorization_file:
            file_open = open(path + FORWARD_SLASH + files, "r")
            for line in file_open:
                line = line.rstrip()
                if "=" in line:
                    line_split = line.split("=")
                    if line_split[0] == "authorization-type":
                        authorization_info["authorization_type"] = line_split[1]
                    elif line_split[0] == "realm":
                        authorization_info["realm"] = line_split[1]
                elif ":" in line:
                    list_users.append(line)
            file_open.close()
            authorization_info["users"]= list_users
            return authorization_info
    return None
