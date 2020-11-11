import time
import os
import json
import sys
import subprocess
import util
import jsn.jsn as jsn
import getpass
import base64
import os
import cryptography
import importlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# prompts user for password to access encrypted credentials files
def prompt_password():
    password = getpass.getpass("Enter Password: ")
    password = bytes(password, encoding='utf8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=bytes("pmbuild", encoding='utf8'),
        length=32,
        iterations=100000
    )
    return base64.urlsafe_b64encode(kdf.derive(password))


# reads and decodes credentials into dict, taking key from prompt_password
def read_and_decode_credentials(key):
    f = Fernet(key)
    if os.path.exists("credentials.bin"):
        while True:
            try:
                credentials = open("credentials.bin", "rb")
                credentials = f.decrypt(credentials.read())
                break
            except (cryptography.exceptions.InvalidSignature, cryptography.fernet.InvalidToken):
                key = prompt_password()
                f = Fernet(key)
        credentials = jsn.loads(credentials.decode("utf-8"))
        return credentials
    return None


# looks up credentials files and retrieves passwords or keys
def lookup_credentials(lookup):
    if not os.path.exists("credentials.bin"):
        print("[error] no credentials file found, run pmbuild -credentials to create and edit one.")
    key = prompt_password()
    credentials = read_and_decode_credentials(key)
    if lookup in credentials.keys():
        return credentials[lookup]
    print("[error] missing credentials for " + lookup)
    exit(1)


# decrypt credential files into credentials.unlocked.jsn to allow user edits, and the encrypts into credentials.bin
def edit_credentials():
    credentials = {
        "example_user": "example_password",
        "another_user": "another_password"
    }
    if not os.path.exists("credentials.bin"):
        print("Create new credentials file encrypted with password:")
    key = prompt_password()
    f = Fernet(key)
    if os.path.exists("credentials.bin"):
        credentials = read_and_decode_credentials(key)
    file = open("credentials.unlocked.jsn", "w+")
    file.write(json.dumps(credentials, indent=4))
    file.close()
    subprocess.call("open credentials.unlocked.jsn", shell=True)
    print("Make changes in credentials.unlocked.jsn")
    input("Then Press Enter to continue...")
    file = open("credentials.unlocked.jsn", "r")
    new_credentials = json.dumps(jsn.loads(file.read()), indent=4)
    os.remove("credentials.unlocked.jsn")
    file = open("credentials.bin", "wb+")
    token = f.encrypt(bytes(new_credentials, encoding='utf8'))
    file.write(token)


# connects to a network location via smb, net use
def connect_to_server(config, task_name):
    print("hello")
    cfg = config[task_name]

    '''
    if not os.path.exists(cfg["project"]):
        if os.name == "posix":
            cmd = "open " + util.inQuotes("smb://" + cfg["user"] + ":" + cfg["password"] + "@" + cfg["address"] + "/" + cfg["mount"])
            p = subprocess.Popen(cmd, shell=True)
            e = p.wait()
        else:
            cmd = "net use " + cfg["address"] + " /user:" + cfg["user"] + " " + cfg["password"]
            p = subprocess.Popen(cmd, shell=True)
            e = p.wait()
    # tries until we get permission
    tries = 10
    while tries > 0:
        try:
            os.listdir(cfg["project"])
            break
        except (PermissionError, FileNotFoundError):
            time.sleep(1)
            tries -= 1
            if tries < 0:
                print("error: media server is not connected")
                return
    print("success: media server connected")
    _mediaServerConnected = True
    '''


# copes files from src to destination
def copy(config, task_name):
    pass


# deletes files and directories specified in files
def clean(config, task_name):
    pass


# configure user settings for each platform
def configure_user(config, args):
    config_user = dict()
    if os.path.exists("config.user.jsn"):
        config_user = jsn.loads(open("config.user.jsn", "r").read())
    if util.get_platform_name() == "win32":
        if "-msbuild" not in sys.argv:
            configure_vc_vars_all(config_user)
            configure_windows_sdk(config_user)
    if os.path.exists("config.user.jsn"):
        config_user = jsn.loads(open("config.user.jsn", "r").read())
        util.merge_dicts(config, config_user)
        
        
# stub for jobs to do nothing
def stub(config):
    pass
    

# runs a generic tool
def run(config, task_name, tool, files):
    exe = config["tools"][tool]
    cmd = exe + " "
    for arg in config[task_name]["args"]:
        cmd += arg + " "
    for file in files:
        p = subprocess.Popen(cmd, shell=True)
        p.wait()


# main function
def main():
    start_time = time.time()

    # must have config.json in working directory
    if not os.path.exists("config.jsn"):
        print("[error] no config.json in current directory.")
        exit(1)

    # load jsn, inherit etc
    config_all = jsn.loads(open("config.jsn", "r").read())

    # special modes
    if "-credentials" in sys.argv:
        edit_credentials()
        return

    # switch between help and run mode
    call = "run"
    if "-help" in sys.argv:
        call = "help"
        
    # first arg is build profile, load profile and merge the config for platform
    if call == "run":
        if sys.argv[1] not in config_all:
            print("[error] " + sys.argv[1] + " is not a valid pmbuild profile")
            exit(0)
        config = config_all[sys.argv[1]]
        # load config user for user specific values (sdk version, vcvarsall.bat etc.)
        configure_user(config, sys.argv)
    else:
        config = config_all["base"]

    # inject task keys, to allow alias jobs and multiple runs of the same thing
    for task_name in config.keys():
        task = config[task_name]
        if "type" not in task.keys():
            config[task_name]["type"] = task_name

    # obtain tools for this platform
    config["tools"] = config_all["tools"]
    if "-cfg" in sys.argv:
        print(json.dumps(config, indent=4))

    # core scripts
    scripts = {
        "copy": copy,
        "connect_to_server": connect_to_server,
        
    }

    # add extensions
    for ext_name in config_all["extensions"].keys():
        ext = config_all["extensions"][ext_name]
        ext_module = importlib.import_module(ext["module"])
        scripts[ext_name] = getattr(ext_module, ext["function"])

    # run tasks
    for task_name in config.keys():
        task = config[task_name]
        print(task)
        if "type" not in task:
            continue
        task_type = task["type"]
        if task_type in config["tools"].keys():
            util.print_header(task_name)
            if "files" in task.keys():
                print("for files job " + task_name)
                # run(config, task_name, task_type, [""])
            else:
                print("single run job " + task_name)
                # run(config, task_name, task_type, [""])
        elif task_type in scripts.keys():
            scripts.get(task_type)(config, task_name)
            pass

    util.print_duration(start_time)


# entry point of pmbuild
if __name__ == "__main__":
    print("--------------------------------------------------------------------------------")
    print("pmbuild (v4) -------------------------------------------------------------------")
    print("--------------------------------------------------------------------------------")
    print("")
    main()
