import time
import json
import sys
import subprocess
import getpass
import base64
import os
import importlib
import glob
import re
import shutil
import cryptography
import util
import jsn.jsn as jsn
import cgu.cgu as cgu
import dependencies

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
    if not key:
        key = prompt_password()
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


# writes a required value input by the user, into config.user.jsn
def update_user_config(k, v, config):
    config[k] = v
    user = dict()
    if os.path.exists("config.user.jsn"):
        user = jsn.loads(open("config.user.jsn", "r").read())
    user[k] = v
    bj = open("config.user.jsn", "w+")
    bj.write(json.dumps(user, indent=4))
    bj.close()


# locate latest version of the windows sdk
def locate_windows_sdk():
    pf_env = ["PROGRAMFILES", "PROGRAMFILES(X86)"]
    sdk = "Windows Kits"
    sdk_dir = None
    for v in pf_env:
        print(v)
        d = os.environ[v]
        if d:
            if sdk in os.listdir(d):
                print(sdk)
                print(d)
                sdk_dir = os.path.join(d, sdk)
                break
    if sdk_dir:
        versions = sorted(os.listdir(sdk_dir), reverse=False)
        if len(versions) > 0:
            if versions[0] == "10":
                # windows 10 has sub versions
                source = os.path.join(sdk_dir, versions[0], "Source")
                if os.path.exists(source):
                    sub_versions = sorted(os.listdir(source), reverse=False)
                    if len(sub_versions) > 0:
                        return str(sub_versions[0])
            else:
                # 8.1
                return str(versions[0])
    return None


# windows only, prompt user to supply their windows sdk version
def configure_windows_sdk(config):
    if "sdk_version" in config.keys():
        return
    # attempt to auto locate
    auto_sdk = locate_windows_sdk()
    if auto_sdk:
        update_user_config("sdk_version", auto_sdk, config)
        return
    print("Windows SDK version not set.")
    print("Please enter the windows sdk you want to use.")
    print("You can find available sdk versions in:")
    print("Visual Studio > Project Properties > General > Windows SDK Version.")
    input_sdk = str(input())
    update_user_config("sdk_version", input_sdk, config)
    return


# find visual studio installation directory
def locate_vs_root():
    pf_env = ["PROGRAMFILES", "PROGRAMFILES(X86)"]
    vs = "Microsoft Visual Studio"
    vs_dir = ""
    for v in pf_env:
        d = os.environ[v]
        if d:
            if vs in os.listdir(d):
                vs_dir = os.path.join(d, vs)
                break
    return vs_dir


# find latest visual studio version
def locate_vs_latest():
    vs_dir = locate_vs_root()
    if len(vs_dir) == 0:
        print("[warning]: could not auto locate visual studio, using vs2017 as default")
        return "vs2017"
    supported = ["2017", "2019"]
    versions = sorted(os.listdir(vs_dir), reverse=False)
    for v in versions:
        if v in supported:
            return "vs" + v


# attempt to locate vc vars all by looking in program files, and finding visual studio installations
def locate_vc_vars_all():
    vs_dir = locate_vs_root()
    if len(vs_dir) == 0:
        return None
    pattern = os.path.join(vs_dir, "**/vcvarsall.bat")
    # if we reverse sort then we get the latest vs version
    vc_vars = sorted(glob.glob(pattern, recursive=True), reverse=False)
    if len(vc_vars) > 0:
        return vc_vars[0]
    return None


# windows only, configure vcvarsall directory for commandline vc compilation
def configure_vc_vars_all(config):
    # already exists
    if "vcvarsall_dir" in config.keys():
        if os.path.exists(config["vcvarsall_dir"]):
            return
    # attempt to auto locate
    auto_vc_vars = locate_vc_vars_all()
    if auto_vc_vars:
        auto_vc_vars = os.path.dirname(auto_vc_vars)
        update_user_config("vcvarsall_dir", auto_vc_vars, config)
        return
    # user input
    while True:
        print("Cannot find 'vcvarsall.bat'")
        print("Please enter the full path to the msvc installation directory containing vcvarsall.bat")
        input_dir = str(input())
        input_dir = input_dir.strip("\"")
        input_dir = os.path.normpath(input_dir)
        if os.path.isfile(input_dir):
            input_dir = os.path.dirname(input_dir)
        if os.path.exists(input_dir):
            update_user_config("vcvarsall_dir", input_dir, config)
            return
        else:
            time.sleep(1)


# apple only, ask user for their team id to insert into xcode projects
def configure_teamid(config):
    if "teamid" in config.keys():
        return
    print("Apple Developer Team ID not set.")
    print("Please enter your development team ID ie. (5B1Y99TY8K)")
    print("You can find team id's or personal team id on the Apple Developer website")
    print("Optionally leave this blank and you select a team later in xcode:")
    print("  Project > Signing & Capabilities > Team")
    input_sdk = str(input())
    update_user_config("teamid", input_sdk, config)
    return


# configure user settings for each platform
def configure_user(config, args):
    config_user = dict()
    if os.path.exists("config.user.jsn"):
        config_user = jsn.loads(open("config.user.jsn", "r").read())
    if util.get_platform_name() == "windows":
        if "-msbuild" not in sys.argv:
            configure_vc_vars_all(config_user)
            configure_windows_sdk(config_user)
    if os.path.exists("config.user.jsn"):
        config_user = jsn.loads(open("config.user.jsn", "r").read())
        util.merge_dicts(config, config_user)


# connects to a network location via smb, net use
def connect(config, task_name):
    cfg = config[task_name]
    mount_path = util.get_platform_network_path(cfg["address"], cfg["mount"])
    if not os.path.exists(mount_path):
        user_pass = ""
        if "credentials" in cfg:
            j = lookup_credentials(cfg["credentials"])
            user_pass = cfg["credentials"] + ":" + str(j) + "@"
        if os.name == "posix":
            cmd = "open " + cgu.in_quotes("smb://" + user_pass + cfg["address"] + "/" + cfg["mount"])
            p = subprocess.Popen(cmd, shell=True)
            p.wait()
        else:
            cmd = "net use " + cfg["address"] + " /user:" + cfg["user"] + " " + cfg["password"]
            p = subprocess.Popen(cmd, shell=True)
            p.wait()
    # tries until we get permission
    tries = 10
    while tries > 0:
        try:
            os.listdir(mount_path)
            break
        except (PermissionError, FileNotFoundError):
            time.sleep(1)
            tries -= 1
            if tries < 0:
                print("error: server is not connected")
                return
    print("success: server connected")


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
        for directory in clean_task["directories"]:
            shutil.rmtree(directory, ignore_errors=True)


# gets file list for task parsing a regex
def get_task_files_regex(files_task):
    regex = re.compile(files_task["match"])
    file_list = util.walk(files_task["directory"])
    pairs = []
    for file in file_list:
        if re.match(regex, file):
            res = file
            for sub in files_task["sub"]:
                pattern = re.compile(sub[0])
                res = re.sub(pattern, sub[1], res)
            pairs.append((util.sanitize_file_path(file), util.sanitize_file_path(res)))
    return pairs


# gets file list for task parsing a glob
def get_task_files_glob(files_task):
    pairs = []
    inputs = glob.glob(files_task[0], recursive=True)
    for src in inputs:
        src_glob_pos = files_task[0].find("*")
        src_root = util.sanitize_file_path(files_task[0][:src_glob_pos - 1])
        dst_root = util.sanitize_file_path(files_task[1])
        src = util.sanitize_file_path(src)
        rp = src.find(src_root) + len(src_root)
        dst = src[:rp].replace(src_root, dst_root) + src[rp:]
        pairs.append((util.sanitize_file_path(src), util.sanitize_file_path(dst)))
    return pairs


# gets task files from a directory, or a single file
def get_task_files_raw(files_task):
    pairs = []
    if os.path.isdir(files_task[0]):
        # dir
        file_list = util.walk(files_task[0])
        for file in file_list:
            src = file
            dst = src.replace(util.sanitize_file_path(files_task[0]), util.sanitize_file_path(files_task[1]))
            pairs.append((src, dst))
    else:
        # single file
        pairs.append((util.sanitize_file_path(files_task[0]), util.sanitize_file_path(files_task[1])))
    return pairs


# takes a tasks files objects and extracts a tuple(input, output) list from directory, single files, glob or regex
def get_task_files(config, task_name):
    files_array = config[task_name]["files"]
    pairs = []
    for files_task in files_array:
        if type(files_task) == dict:
            pairs.extend(get_task_files_regex(files_task))
        else:
            if len(files_task) != 2:
                print("ERROR: file tasks must be an array of size 2 [src, dst]")
                exit(1)
            if files_task[0].find("*") != -1:
                pairs.extend(get_task_files_glob(files_task))
            else:
                pairs.extend(get_task_files_raw(files_task))
    change_ext = ""
    if util.value_with_default("change_ext", config[task_name], False):
        change_ext = config[task_name]["change_ext"]
    if util.value_with_default("strip_ext", config[task_name], False) or len(change_ext) > 0:
        stripped = []
        for output in pairs:
            changed = util.change_ext(output[1], change_ext)
            stripped.append((output[0], changed))
        pairs = stripped
    return pairs


# returns expanded list of file from matches where each list element of files can be a glob, regex match or single file
def expand_rules_files(export_config, task_name, subdir):
    if "rules" not in export_config[task_name]:
        return
    rules = export_config[task_name]["rules"]
    presets = export_config[task_name]["presets"]
    for rule in rules.keys():
        rule_config = rules[rule]
        expanded_files = []
        for file_match in rule_config["files"]:
            if type(file_match) == list:
                regex = re.compile(file_match[0])
                file_list = util.walk(subdir)
                for file in file_list:
                    if re.match(regex, file):
                        expanded_files.append(file)
            elif file_match.find("*") != -1:
                expanded_files.extend(glob.glob(os.path.join(subdir, file_match), recursive=True))
            else:
                expanded_files.append(os.path.join(subdir, file_match))
        rule_config["files"] = []
        for file in expanded_files:
            rule_config["files"].append(file)
        # expand preset
        if "preset" in rule_config.keys():
            if rule_config["preset"] in presets:
                for key in presets[rule_config["preset"]].keys():
                    rule_config[key] = presets[rule_config["preset"]][key]
            rule_config.pop("preset")
    export_config[task_name].pop("presets")


# look for export.json in directory tree, combine and override exports by depth, override further by rules
def export_config_for_directory(task_name, directory):
    file_path = util.sanitize_file_path(directory)
    dirt_tree = file_path.split(os.sep)
    export_dict = dict()
    subdir = ""
    for i in range(0, len(dirt_tree)):
        subdir = os.path.join(subdir, dirt_tree[i])
        export = os.path.join(subdir, "export.jsn")
        if os.path.exists(export):
            dir_export_config = jsn.loads(open(export, "r").read())
            expand_rules_files(dir_export_config, task_name, subdir)
            util.merge_dicts(export_dict, dir_export_config)
    return export_dict


# apply config rules for file
def apply_export_config_rules(export_config, task_name, filename):
    cfg = export_config[task_name]
    file_config = dict()
    for key in cfg.keys():
        if key == "rules":
            continue
        file_config[key] = cfg[key]
    if "rules" in export_config[task_name]:
        rules = export_config[task_name]["rules"]
        for rule in rules.keys():
            rule_config = rules[rule]
            files = rule_config["files"]
            if filename in files:
                util.merge_dicts(file_config, rule_config)
                file_config.pop("files", None)
    return file_config


# get file specific export config from the nested directory structure, apply rules to specific files
def export_config_for_file(task_name, filename):
    dir_config = export_config_for_directory(task_name, os.path.dirname(filename))
    print(json.dumps(dir_config, indent=4))
    file_config = apply_export_config_rules(dir_config, task_name, filename)
    return file_config


# expand args evaluating %{input_file}, %{output_file} and %{export_args}
def expand_args(args, task_name, input_file, output_file):
    cmd = ""
    for arg in args:
        arg = arg.replace("%{input_file}", input_file)
        arg = arg.replace("%{output_file}", output_file)
        if arg.find("%{export_args}") != -1:
            export_config = export_config_for_file(task_name, input_file)
            arg = ""
            for export_arg in export_config.keys():
                val = " " + str(export_config[export_arg])
                if type(export_config[export_arg]) == bool:
                    if not export_config[export_arg]:
                        continue
                    else:
                        val = ""
                arg += export_arg + val + " "
            arg = arg.strip()
        cmd += arg + " "
    return cmd


# runs a generic tool
def run_tool(config, task_name, tool, files):
    deps = True
    exe = config["tools"][tool]
    for file in files:
        cmd = exe + " "
        cmd += expand_args(config[task_name]["args"], task_name, file[0], file[1])
        util.create_dir(file[1])
        if deps:
            d = dependencies.create_dependency_single(file[0], file[1], cmd)
            if dependencies.check_up_to_date_single(file[1], d):
                continue
        util.log_lvl(cmd, config, "-verbose")
        p = subprocess.Popen(cmd, shell=True)
        e = p.wait()
        if e == 0:
            dependencies.write_to_file_single(d, file[1])



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

    # special args passed from user
    special_args = [
        "-credentials",
        "-help",
        "-verbose",
        "-dry",
        "-silent",
        "-cfg",
        "-clean",
        "-all"
    ]

    for arg in reversed(special_args):
        if arg not in sys.argv:
            special_args.remove(arg)
        else:
            sys.argv.remove(arg)

    # add implicit all
    if len(sys.argv) == 2:
        special_args.append("-all")

    # special modes
    if "-credentials" in special_args:
        edit_credentials()
        return

    # switch between help and run mode
    call = "run"
    if "-help" in special_args:
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

    config["special_args"] = special_args

    # obtain tools for this platform
    config["tools"] = config_all["tools"]
    if "-cfg" in special_args:
        print(sys.argv)
        print(special_args)
        print(json.dumps(config, indent=4))

    # core scripts
    scripts = {
        "copy": copy,
        "connect": connect,
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
    if "-clean" in special_args:
        for task_name in config.keys():
            task = config[task_name]
            if "type" not in task:
                continue
            if task["type"] == "clean":
                util.print_header(task_name)
                clean(config, task_name)

    # filter tasks
    runnable = []
    for task_name in config.keys():
        task = config[task_name]
        if "type" not in task:
            continue
        if "type" == "clean":
            continue
        if "-n" + task_name in sys.argv:
            continue
        if "-" + task_name in sys.argv or "-all" in special_args:
            runnable.append(task_name)

    # run tasks
    for task_name in runnable:
        task = config[task_name]
        if "type" not in task:
            continue
        if "type" == "clean":
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
