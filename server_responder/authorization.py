import os
import sys

def check_authorization_directory(config, path):
    try:
        authorization_info = None
        while authorization_info is None and path != config["MAPPING"]["root_dir"]:
            if os.path.isdir(path):
                authorization_info = fill_authorization(config, path)
            if authorization_info is None:
                path = path.rsplit("/", 1)[0]
            else:
                sys.stdout.write(f'check_authorization_directory : authorization_info {authorization_info}\n ')
                return authorization_info
    except Exception as e:
        sys.stderr.write(f'check_authorization_directory : error {e}\n')
    return None


def fill_authorization(config_instance, path):
    authorization_info = get_auth_structure()
    list_users = []
    for files in os.listdir(path):
        if files == config_instance["MAPPING"]["DEFAULT_AUTHORIZATION_FILE"]:
            file_open = open(os.path.join(path, files), "r")
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

def get_auth_structure():
    return {
        "authorization_type": None,
        "realm": None,
        "users": None
    }


'''
Function to write to authorization file
'''
def write_authorization_file(report, nonce, nc, authorization_info, qop, opaque, config):
    sys.stdout.write("write_authorization_file\n")
    if os.path.exists(config["MAPPING"]["root_dir"] + "/DigestAuthorizationInfo.txt"):
        file_authorization = open(config["MAPPING"]["root_dir"] + "/DigestAuthorizationInfo.txt", "w")
    else:
        file_authorization = open(config["MAPPING"]["root_dir"] + "/DigestAuthorizationInfo.txt", "w")
    file_authorization.write("user: " + "|url:" + report["request"]["path"] + "|nonce:" + nonce + "|nc:" + str(nc)
                                + "|realm:" + authorization_info["realm"] + "|qop:" + qop + "|opaque:" + opaque + "\n")
    file_authorization.close()