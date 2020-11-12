import time
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
import glob
import re
import shutil
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# stub for jobs to do nothing
def stub(config):
    pass


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


# copes files from src to destination only if newer
def copy(config, task_name, files):
    for file in files:
        util.copy_file_create_dir_if_newer(file[0], file[1])


# deletes files and directories specified in files
def clean(config, task_name):
    clean_task = config[task_name]
    if "files" in clean_task:
        files = get_task_files(config, task_name)
    if "directories" in clean_task:
        for dir in clean_task["directories"]:
            shutil.rmtree(dir, ignore_errors=True)


# takes a taks files objects and extracts a file list from directory, single files, glob or regex
def get_task_files(config, task_name):
    outputs = []
    files_array = config[task_name]["files"]
    sanitized_outputs = []
    for files_task in files_array:
        if type(files_task) == dict:
            print("regex!")
            regex = re.compile(files_task["match"])
            file_list = []
            for root, dirs, files in os.walk(files_task["directory"]):
                for file in files:
                    file_list.append(util.sanitize_file_path(os.path.join(root, file)))
            for file in file_list:
                if re.match(regex, file):
                    res = file
                    for sub in files_task["sub"]:
                        pattern = re.compile(sub[0])
                        res = re.sub(pattern, sub[1], res)
                    sanitized_outputs.append((file, util.sanitize_file_path(res)))
        else:
            if len(files_task) != 2:
                print("ERROR: file tasks must be an array of size 2 [src, dst]")
                exit(1)
            inputs = glob.glob(files_task[0], recursive=True)
            if len(inputs) > 1:
                for src in inputs:
                    src_glob_pos = files_task[0].find("*")
                    src_root = util.sanitize_file_path(files_task[0][:src_glob_pos - 1])
                    dst_root = util.sanitize_file_path(files_task[1])
                    src = util.sanitize_file_path(src)
                    rp = src.find(src_root) + len(src_root)
                    dst = src[:rp].replace(src_root, dst_root) + src[rp:]
                    outputs.append((src, dst))
            elif len(inputs) == 1:
                if os.path.isdir(files_task[0]):
                    # dir
                    for root, dirs, files in os.walk(files_task[0]):
                        for file in files:
                            src = util.sanitize_file_path(os.path.join(root, file))
                            dst = src.replace(util.sanitize_file_path(files_task[0]), util.sanitize_file_path(files_task[1]))
                            outputs.append((src, dst))
                else:
                    # single file
                    outputs.append((files_task[0], files_task[1]))
            for pair in outputs:
                sanitized_outputs.append((util.sanitize_file_path(pair[0]), util.sanitize_file_path(pair[1])))
    return sanitized_outputs


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


# expand args evaluating %{input_file}, %{output_file} and %{export_args}
def expand_args(args, input_file, output_file):
    print(args)
    cmd = ""
    for arg in args:
        arg = arg.replace("%{input_file}", input_file)
        arg = arg.replace("%{output_file}", output_file)
        if arg.find("%{export_args}") != -1:
            arg = "-t RGBA8"
        cmd += arg + " "
    return cmd


# runs a generic tool
def run_tool(config, task_name, tool, files):
    exe = config["tools"][tool]
    for file in files:
        cmd = exe + " "
        cmd += expand_args(config[task_name]["args"], file[0], file[1])
        print(cmd)
        # p = subprocess.Popen(cmd, shell=True)
        # p.wait()


# runs shell commands in the current environment
def shell(config, task_name):
    commands = config[task_name]["commands"]
    if type(commands) != list:
        print("[error] shell must be array of strings")
    for cmd in commands:
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
        "make": None,
        "lunch": None,
        "shell": shell
    }

    # add extensions
    for ext_name in config_all["extensions"].keys():
        ext = config_all["extensions"][ext_name]
        ext_module = importlib.import_module(ext["module"])
        scripts[ext_name] = getattr(ext_module, ext["function"])

    # cleans are special operations which runs first
    if "-clean" in sys.argv:
        for task_name in config.keys():
            task = config[task_name]
            if "type" not in task:
                continue
            if task["type"] == "clean":
                util.print_header(task_name)
                clean(config, task_name)

    # run tasks
    for task_name in config.keys():
        task = config[task_name]
        if "type" not in task:
            continue
        util.print_header(task_name)
        task_type = task["type"]
        if task_type in config["tools"].keys():
            if "files" in task.keys():
                run_tool(config, task_name, task_type, get_task_files(config, task_name))
            else:
                run_tool(config, task_name, task_type, [""])
        elif task_type in scripts.keys():
            if "files" in task.keys():
                scripts.get(task_type)(config, task_name, get_task_files(config, task_name))
            else:
                scripts.get(task_type)(config, task_name)
            pass

    util.print_duration(start_time)


# entry point of pmbuild
if __name__ == "__main__":
    util.print_header("pmbuild (v4)")
    main()
