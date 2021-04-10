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
import threading
import webbrowser
import fnmatch
import zipfile

import util
import dependencies
import jsn.jsn as jsn
import cgu.cgu as cgu

from http.server import HTTPServer, CGIHTTPRequestHandler

# exit's on error but allows user to choose not to
def error_exit(config):
    if "ignore_errors" not in config["special_args"]:
        sys.exit(1)


# prompts user for password to access encrypted credentials files
def prompt_password():
    import cryptography
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
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
    import cryptography
    from cryptography.fernet import Fernet
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
        print(credentials)
        return credentials
    return None


# looks up credentials files and retrieves passwords or keys
def lookup_credentials(config, lookup):
    if not os.path.exists("credentials.bin"):
        print("[error] no credentials file found, run pmbuild -credentials to create and edit one.")
    key = prompt_password()
    credentials = read_and_decode_credentials(key)
    if lookup in credentials.keys():
        return credentials[lookup]
    print("[error] missing credentials for " + lookup)
    error_exit(config)


# decrypt credential files into credentials.unlocked.jsn to allow user edits, and the encrypts into credentials.bin
def edit_credentials():
    import cryptography
    from cryptography.fernet import Fernet
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
    util.open_text_editor("credentials.unlocked.jsn")
    print("Make changes in credentials.unlocked.jsn")
    input("Then Press Enter to continue...")
    file = open("credentials.unlocked.jsn", "r")
    new_credentials = json.dumps(jsn.loads(file.read()), indent=4)
    file.close()
    os.remove("credentials.unlocked.jsn")
    file = open("credentials.bin", "wb+")
    token = f.encrypt(bytes(new_credentials, encoding='utf8'))
    file.write(token)


# writes a required value input by the user, into config.user.jsn
def update_user_config(k, v, config):
    if "user_vars" not in config:
        config["user_vars"] = dict()
    config["user_vars"][k] = v
    user = dict()
    user["user_vars"] = dict()
    if os.path.exists("config.user.jsn"):
        user["user_vars"] = jsn.loads(open("config.user.jsn", "r").read())["user_vars"]
    user["user_vars"][k] = v
    bj = open("config.user.jsn", "w+")
    bj.write(json.dumps(user, indent=4))
    bj.close()


# locate latest version of the windows sdk
def locate_windows_sdk():
    pf_env = ["PROGRAMFILES", "PROGRAMFILES(X86)"]
    sdk = "Windows Kits"
    sdk_dir = None
    for v in pf_env:
        d = os.environ[v]
        if d:
            if sdk in os.listdir(d):
                sdk_dir = os.path.join(d, sdk)
                break
    if sdk_dir:
        versions = sorted(os.listdir(sdk_dir), reverse=False)
        if len(versions) > 0:
            if versions[0] == "10":
                # windows 10 has sub versions
                source = os.path.join(sdk_dir, versions[0], "Source")
                if os.path.exists(source):
                    sub_versions = sorted(os.listdir(source), reverse=True)
                    if len(sub_versions) > 0:
                        return str(sub_versions[0])
            else:
                # 8.1
                return str(versions[0])
    return None


# windows only, prompt user to supply their windows sdk version
def configure_windows_sdk(config):
    if "windows_sdk_version" in config.keys():
        return
    # attempt to auto locate
    auto_sdk = locate_windows_sdk()
    if auto_sdk:
        update_user_config("windows_sdk_version", auto_sdk, config)
        return
    print("Windows SDK version not set.")
    print("Please enter the windows sdk you want to use.")
    print("You can find available sdk versions in:")
    print("Visual Studio > Project Properties > General > Windows SDK Version.")
    input_sdk = str(input())
    update_user_config("windows_sdk_version", input_sdk, config)
    return


# generates launch and task files for vscode
def vscode_build(config, task_name, files):
    vscode_config = config[task_name]
    tasks = {
        "version": "2.0.0",
        "tasks": []
    }
    launch = {
        "version": "0.2.0",
        "configurations": []
    }
    workspace = {
        "folders": []
    }
    relative_path = ".."
    if "folders" in vscode_config.keys():
        for folder in vscode_config["folders"]:
            workspace["folders"].append({"path": os.path.join(relative_path, folder)})
    workspace["folders"].append({"path": "."})
    cwd = util.value_with_default("cwd", vscode_config, "")
    debugger_type = "cppdbg"
    debugger = util.value_with_default("debugger", vscode_config, "lldb")
    if debugger == "vscode":
        debugger_type = "cppvsdbg"
    for file in files:
        for configuration in vscode_config["configurations"]:
            target_name = os.path.basename(file[0])
            make_cmd = configuration["make"].replace("%{target_name}", target_name)
            vscode_config_name = target_name + "_" + configuration["name"]
            vscode_task_name = "build_" + target_name + "_" + configuration["name"]
            print("build target: " + vscode_config_name)
            tasks["tasks"].append({
                "label": vscode_task_name,
                "command": make_cmd,
                "type": "shell"
            })
            launch_cmd = configuration["launch"].replace("%{target_name}", target_name)
            launch["configurations"].append(
                {
                    "name": vscode_config_name,
                    "type": debugger_type,
                    "request": "launch",
                    "program": "${workspaceFolder}/" + launch_cmd,
                    "args": [],
                    "stopAtEntry": False,
                    "preLaunchTask": vscode_task_name,
                    "cwd": "${workspaceFolder}/" + cwd,
                    "environment": [],
                    "externalConsole": False,
                    "MIMode": debugger
                }
            )
    workspace_file = os.path.join(".vscode", "workspace.code-workspace")
    launch_file = os.path.join(".vscode", "launch.json")
    tasks_file = os.path.join(".vscode", "tasks.json")
    util.create_dir(tasks_file)
    open(launch_file, "w+").write(json.dumps(launch, indent=4))
    open(tasks_file, "w+").write(json.dumps(tasks, indent=4))
    open(workspace_file, "w+").write(json.dumps(workspace, indent=4))


# find visual studio installation directory
def locate_vs_root():
    pf_env = ["PROGRAMFILES", "PROGRAMFILES(X86)"]
    vs = "Microsoft Visual Studio"
    vs_dir = ""
    for v in pf_env:
        if v in os.environ:
            d = os.environ[v]
            if d:
                if vs in os.listdir(d):
                    vs_dir = os.path.join(d, vs)
                    break
    return vs_dir


# find latest visual studio version
def locate_vs_latest(config):
    vs_dir = locate_vs_root()
    if len(vs_dir) > 0:
        supported = ["2015", "2017", "2019"]
        versions = sorted(os.listdir(vs_dir), reverse=False)
        for v in versions:
            if v in supported:
                update_user_config("vs_latest", "vs" + str(versions[0]), config)
                return "vs" + v
        print("[warning] could not locate valid visual studio installation in: " + vs_dir)
    # ensure we have vcvars all and try figuring out vs version from there
    configure_vc_vars_all(config)
    if "vcvarsall_dir" in config.keys():
        vcva = config["vcvarsall_dir"]
        vs = "Microsoft Visual Studio"
        if vs in vcva:
            dirs = vcva.split(os.sep)
            for i in range(0, len(dirs)):
                if dirs[i] == vs and i < len(dirs):
                    vs_version = "vs" + dirs[i+1]
                    print("[vs_latest] found " + vs_version + " from vcvarsall_dir (" + vcva + ")")
                    update_user_config("vs_latest", vs_version, config)
                    return vs_version
    print("[warning] could not auto detect vs_latest, using vs2019 as default")
    update_user_config("vs_latest", "vs2019", config)
    return "vs2019"


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


# attempt to locate vc vars all by looking in program files, and finding visual studio installations
def locate_msbulild():
    vs_dir = locate_vs_root()
    if len(vs_dir) == 0:
        return None
    pattern = os.path.join(vs_dir, "**/msbuild.exe")
    # if we reverse sort then we get the latest
    msbuild = sorted(glob.glob(pattern, recursive=True), reverse=False)
    if len(msbuild) > 0:
        return msbuild[0]
    return None


# gets location of msbuild to invoke
def get_msbuild():
    msbuild = locate_msbulild()
    if not msbuild:
        msbuild = "msbuild"
    else:
        msbuild = cgu.in_quotes(msbuild)
    return msbuild


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


# calls vcvars all to setup the current environment to be able to use msbuild
def setup_vcvars(config):
    return "pushd \ && cd \"" + config["user_vars"]["vcvarsall_dir"] + "\" && vcvarsall.bat x86_amd64 && popd"


# apple only, ask user for their team id to insert into xcode projects
def configure_teamid(config):
    if "user_vars" in config.keys():
        if "teamid" in config["user_vars"].keys():
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
    config_user["user_vars"] = dict()
    if os.path.exists("config.user.jsn"):
        config_user = jsn.loads(open("config.user.jsn", "r").read())
    if util.get_platform_name() == "windows":
        if "-msbuild" not in sys.argv:
            locate_vs_latest(config_user["user_vars"])
            configure_vc_vars_all(config_user["user_vars"])
            configure_windows_sdk(config_user["user_vars"])
            util.log_lvl(config_user["vs_latest"], config, "-verbose")
            util.log_lvl(config_user["windows_sdk"], config, "-verbose")
    if os.path.exists("config.user.jsn"):
        config_user = jsn.loads(open("config.user.jsn", "r").read())
        util.merge_dicts(config, config_user)


# connects to a network location via smb, net use
def connect(config, task_name):
    cfg = config[task_name]
    mount_path = util.get_platform_network_path(cfg["address"], cfg["mount"])
    if not os.path.exists(mount_path):
        user_pass = ""
        if "user" and "password" in cfg:
            user_pass = cfg["user"] + ":" + cfg["password"] + "@"
        elif "credentials" in cfg:
            j = lookup_credentials(config, cfg["credentials"])
            user_pass = cfg["credentials"] + ":" + str(j) + "@"
            cfg["user"] = cfg["credentials"]
            cfg["password"] = str(j)
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


# moves files from src to destination only if newer
def move(config, task_name, files):
    for file in files:
        shutil.move(file[0], file[1])


# zips files into a destination folder, only updating if newer
def zip(config, task_name, files):
    unique_zips = dict()
    for file in files:
        src = file[0]
        dst = file[1]
        zp = dst.find(".zip")
        dst = dst[:zp + 4]
        if dst not in unique_zips.keys():
            unique_zips[dst] = list()
        unique_zips[dst].append(src)
    for dst in unique_zips.keys():
        zloc = os.path.splitext(os.path.basename(dst))[0]
        dir = os.path.dirname(dst)
        util.create_dir(dir)
        with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zip:
            for file in unique_zips[dst]:
                print("zip " + file)
                zip.write(file, os.path.join(zloc, file))


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


# output container in certain formats
def file_list_to_container_format(container, files):
    if "format" in container:
        files = files.strip()
        lines = files.split("\n")
        fmt_files = ""
        for l in lines:
            rep = container["format"].replace("%{container_file}", l)
            fmt_files += rep + "\n"
        return fmt_files
    # default is a list of files separted by new line
    return files


# removes files belonging to excludes, expand containers removing loose files from the list, and inserts the container
def filter_files(config, task_name, files):
    dirs = []
    lookups = dict()
    for file in files:
        dn = os.path.dirname(file[0])
        if dn not in dirs:
            dirs.append(dn)
        excluded = False
        if "excludes" in config[task_name].keys():
            for exclude in config[task_name]["excludes"]:
                if exclude.find("*") != -1:
                    if fnmatch.fnmatch(file[0], exclude):
                        excluded = True
                        break
                elif os.path.basename(file[0]) == exclude:
                    excluded = True
                    break
        if not excluded:
            lookups[file[0]] = (file[0], file[1])
    # check for processing containers
    containers = util.value_with_default("containers", config[task_name], True)
    container_output_ext = util.value_with_default("change_ext", config[task_name], ".txt")
    for directory in dirs:
        en = os.path.join(directory, "export.jsn")
        if os.path.exists(en):
            j = jsn.loads(open(en, "r").read())
            if "container" in j:
                container_dir = os.path.dirname(en)
                bn = os.path.basename(directory)
                dir_files = sorted(os.listdir(directory))
                filtered_files = []
                for file in j["container"]["files"]:
                    if file in dir_files:
                        filtered_files.append(file)
                    else:
                        pattern = file
                        for df in dir_files:
                            if fnmatch.fnmatch(df, pattern):
                                filtered_files.append(df)
                container_files = ""
                dest_file = ""
                for file in filtered_files:
                    fp = os.path.join(directory, file)
                    if fp in lookups:
                        dest_ext = os.path.splitext(lookups[fp][1])[1]
                        dest_dir = os.path.dirname(os.path.dirname(lookups[fp][1]))
                        dest_file = os.path.join(dest_dir, bn + dest_ext)
                        lookups.pop(fp)
                        fp = util.sanitize_file_path(fp)
                        fp = os.path.normpath(fp)
                        fp.replace("\\", "/")
                    container_files += fp + "\n"
                if len(dest_file) == 0:
                    for file in files:
                        if os.path.dirname(file[0]) == container_dir:
                            dest_file = os.path.dirname(file[1]) + container_output_ext
                            break
                container_files = file_list_to_container_format(j["container"], container_files)
                container_file = en.replace("export.jsn", bn + ".container.txt")
                current_files = ""
                newest = 0
                for f in filtered_files:
                    fn = os.path.join(directory, f)
                    newest = max(os.path.getmtime(fn), newest)
                built = 0
                if os.path.exists(container_file):
                    current_files = open(container_file, "r").read()
                    built = os.path.getmtime(container_file)
                if current_files != container_files or newest > built:
                    open(container_file, "w+").write(container_files)
                if containers:
                    lookups[container_file] = (container_file, dest_file)
    pairs = []
    for f in lookups.keys():
        pairs.append((lookups[f][0], lookups[f][1]))
    return pairs


# takes a tasks files objects and extracts a tuple(input, output) list from directory, single files, glob or regex
def get_task_files(config, task_name):
    files_array = config[task_name]["files"]
    pairs = []
    for files_task in files_array:
        change_index = 1
        if type(files_task) == str:
            single = files_task
            files_task = [single, ""]
            change_index = 0
        if type(files_task) == dict:
            pairs.extend(get_task_files_regex(files_task))
        else:
            if files_task[0].find("*") != -1:
                pairs.extend(get_task_files_glob(files_task))
            else:
                pairs.extend(get_task_files_raw(files_task))
    if "change_ext" in config[task_name]:
        change_ext = config[task_name]["change_ext"]
        stripped = []
        for output in pairs:
            changed = util.change_ext(output[change_index], change_ext)
            if change_index == 1:
                stripped.append((output[0], changed))
            elif change_index == 0:
                stripped.append((changed, output[1]))
        pairs = stripped
    pairs = filter_files(config, task_name, pairs)
    return pairs


# returns expanded list of file from matches where each list element of files can be a glob, regex match or single file
def expand_rules_files(export_config, task_name, subdir):
    if task_name not in export_config:
        return
    if "rules" not in export_config[task_name]:
        return
    rules = export_config[task_name]["rules"]
    if "presets" in export_config[task_name]:
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
    if "presets" in export_config[task_name]:
        export_config[task_name].pop("presets")


# look for export.json in directory tree, combine and override exports by depth, override further by rules
def export_config_for_directory(task_name, directory):
    file_path = util.sanitize_file_path(directory)
    dirt_tree = file_path.split(os.sep)
    export_dict = dict()
    subdir = ""
    # handles unix paths /starting/with/
    if (len(file_path) > 0 and file_path[0] == os.sep):
        subdir = os.sep
    for i in range(0, len(dirt_tree)):
        # handles windows drives
        if dirt_tree[i].endswith(":"):
            dirt_tree[i] += os.sep
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
    file_config = apply_export_config_rules(dir_config, task_name, filename)
    return file_config


# expand args evaluating %{input_file}, %{output_file} and %{export_args}
def expand_args(args, config, task_name, input_file, output_file):
    cmd = ""
    for arg in args:
        # hook in input and output files
        arg = arg.replace("%{input_file}", input_file)
        arg = arg.replace("%{output_file}", output_file)
        # expand args from export.jsn
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
        # replace user_vars
        user_vars = [
            "vs_latest",
            "windows_sdk_version",
            "teamid"
        ]
        for uv in user_vars:
            v = "%{" + uv + "}"
            if arg.find(v) != -1:
                if uv == "teamid":
                    configure_teamid(config)
                if uv not in config["user_vars"]:
                    print("[error] missing variable " + uv)
                    error_exit(config)
                arg = arg.replace(v, config["user_vars"][uv])
        cmd += arg + " "
    for arg in config["user_args"]:
        cmd += arg + " "
    cmd = cmd.strip()
    return cmd


# runs a generic tool
def run_tool(config, task_name, tool, files):
    deps = util.value_with_default("dependencies", config[task_name], False)
    exe = util.sanitize_file_path(config["tools"][tool])
    for file in files:
        cmd = exe + " "
        cmd += expand_args(config[task_name]["args"], config, task_name, file[0], file[1])
        if len(file[1]) > 0:
            util.create_dir(file[1])
        if deps:
            d = dependencies.create_dependency_single(file[0], file[1], cmd)
            if dependencies.check_up_to_date_single(file[1], d):
                continue
        util.log_lvl(cmd, config, "-verbose")
        p = subprocess.Popen(cmd, shell=True)
        e = p.wait()
        if e == 0 and deps:
            dependencies.write_to_file_single(d, file[1])
        if e != 0:
            print("[error] processing file " + file[0])
            error_exit(config)


# displays help for generic tool
def run_tool_help(config, task_name, tool):
    tools_help = config["tools_help"]
    exe = util.sanitize_file_path(config["tools"][tool])
    if tool in tools_help.keys():
        tool_help = tools_help[tool]
        p = subprocess.Popen(exe + " " + tool_help["help_arg"], shell=True)
        p.wait()


# runs shell commands in the current environment
def shell(config, task_name):
    if "commands" not in config[task_name]:
        print("[error] shell must specify array of commands:[...]")
        error_exit(config)
    commands = config[task_name]["commands"]
    if type(commands) != list:
        print("[error] shell must be array of strings")
        error_exit(config)
    for cmd in commands:
        util.log_lvl(cmd, config, "-verbose")
        p = subprocess.Popen(cmd, shell=True)
        e = p.wait()
        if e:
            print("[error] running " + cmd)
            error_exit(config)


# generate a cli command for building with different toolchains (make, gcc/clang, xcodebuild, msbuild)
def make_for_toolchain(jsn_config, file, options):
    make_config = jsn_config["make"]
    toolchain = make_config["toolchain"]

    msbuild = ""
    if toolchain == "msbuild":
        msbuild = get_msbuild()

    cmds = {
        "make": "make",
        "emmake": "emmake make",
        "xcodebuild": "xcodebuild",
        "msbuild": msbuild
    }
    cmd = cmds[toolchain]

    target_options = {
        "make": "",
        "emmake": "",
        "xcodebuild": "-project ",
        "msbuild": ""
    }
    target_option = target_options[toolchain]

    # parse other options
    extra_args = ""
    for option in options[1:]:
        # pass through any additional platform specific args
        extra_args += option + " "

    # build final cli command
    if "workspace" in make_config.keys():
        cmdline = cmd + " -workspace " + make_config["workspace"] + " -scheme " + file + " " + extra_args
    else:
        cmdline = cmd + " " + target_option + " " + file + " " + extra_args

    return cmdline


# runs the help for the configured make toolchain
def help_for_make_toolchain(config, toolchain):
    msbuild = ""
    if toolchain == "msbuild":
        msbuild = get_msbuild()
    cmd = {
        "make": "make --help",
        "emmake": "emmake make --help",
        "xcodebuild": "xcodebuild -help",
        "msbuild": msbuild + " /help"
    }
    p = subprocess.Popen(cmd[toolchain], shell=True)
    e = p.wait()


# prints available make targets
def print_make_targets(files):
    print("available make targets:")
    print("    all (builds all the below targets)")
    for file in files:
        print("    " + os.path.splitext(os.path.basename(file[0]))[0])
    print("")


# runs make, and compiles from makefiles, vs solution or xcode project.
def make(config, files, options):
    cwd = os.getcwd()
    if "make" not in config.keys():
        print("[error] make config missing from config.jsn ")
        error_exit(config)
    toolchain = config["make"]["toolchain"]
    if "-help" in config["special_args"]:
        print_make_targets(files)
        help_for_make_toolchain(config, toolchain)
        sys.exit(0)
    if toolchain == "msbuild":
        setup_env = setup_vcvars(config)
        subprocess.call(setup_env, shell=True)
    if len(files) == 0 or len(options) <= 0:
        print("[error] no make target specified")
        print_make_targets(files)
        error_exit(config)
    # filter build files
    build_files = []
    for file in files:
        if options[0] == "all":
            pass
        elif options[0] != os.path.splitext(os.path.basename(file[0]))[0]:
            continue
        build_files.append(file)
    if len(build_files) <= 0:
        print("[error] no make target found for " + str(options))
        print_make_targets(files)
        error_exit(config)
    for file in build_files:
        os.chdir(os.path.dirname(file[0]))
        proj = os.path.basename(file[0])
        cmd = make_for_toolchain(config, proj, options)
        p = subprocess.Popen(cmd, shell=True)
        e = p.wait()
        if e != 0:
            error_exit(config)
        os.chdir(cwd)


# start a simple webserver serving path on port
def start_server(path, port=8000):
    httpd = HTTPServer(('', port), CGIHTTPRequestHandler)
    httpd.serve_forever()


# starts a web server on a thread and loads a sample in the browser
def run_web(cmd):
    port = 8000
    daemon = threading.Thread(name='daemon_server', target=start_server, args=('.', port))
    daemon.setDaemon(True)
    daemon.start()
    chrome_path = {
        "mac": 'open -a /Applications/Google\ Chrome.app %s',
        "windows": "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe %s",
        "linux": ""
    }
    plat = util.get_platform_name()
    webbrowser.get(chrome_path[plat]).open('http://localhost:{}/{}'.format(port, cmd))
    while True:
        time.sleep(1)


# prints available make targets
def print_launch_targets(files):
    print("available launch targets:")
    print("    all (runs all the below targets)")
    for file in files:
        print("    " + os.path.splitext(os.path.basename(file[0]))[0])
    print("")


# launches and exectuable program from the commandline
def launch(config, files, options):
    cwd = os.getcwd()
    run_config = config["launch"]
    if "-help" in config["special_args"]:
        print_launch_targets(files)
        sys.exit(0)
    if len(options) == 0:
        print("[error] no run target specified")
        error_exit(config)
    targets = []
    for file in files:
        file = file[0]
        bn = os.path.basename(file)
        tn = os.path.splitext(bn)[0]
        if options[0] == "all" or options[0] == tn:
            targets.append((os.path.dirname(file), os.path.basename(file), tn))
    if len(targets) == 0:
        print("[error] no run targets found for " + str(options))
        error_exit(config)
    # switch to bin dir
    for t in targets:
        os.chdir(t[0])
        cmd = run_config["cmd"]
        cmd = cmd.replace("%{target_path}", t[1])
        cmd = cmd.replace("%{target_name}", t[2])
        if os.path.splitext(t[1])[1] == ".html":
            run_web(cmd)
        else:
            for o in options[1:]:
                cmd += " " + o
            p = subprocess.Popen(cmd, shell=True)
            e = p.wait()
            print(t[2] + " exited with code: " + str(e))
            if e != 0:
                error_exit(config)
        os.chdir(cwd)


# generates metadata json to put in data root dir, for doing hot loading and other re-build tasks
def generate_pmbuild_config(config, taskname):
    pmbuild_config = config[taskname]
    wd = os.getcwd()
    dd = pmbuild_config["destination"]
    profile = config["user_vars"]["profile"]
    multi = " && "
    pmbuild_config["pmbuild_cmd"] = util.sanitize_file_path(pmbuild_config["pmbuild_cmd"])
    md = {
        "profile": profile,
        "pmbuild_cmd": pmbuild_config["pmbuild_cmd"],
        "pmbuild": "cd " + wd + multi + pmbuild_config["pmbuild_cmd"] + " " + profile + " "
    }
    util.create_dir(dd)
    np = os.path.join(dd, "pmbuild_config.json")
    np = os.path.normpath(np)
    f = open(np, "w+")
    f.write(json.dumps(md, indent=4))


# print available profiles in config.jsn of cwd
def print_profiles(config):
    print("\nprofiles:")
    print("    config.jsn (edit task settings or add profiles in here)")
    non_profiles = [
        "tools",
        "tools_help",
        "extensions",
        "user_vars",
        "special_args",
        "post_build_order",
        "pre_build_order",
        "build_order"
    ]
    for p in config.keys():
        if p not in non_profiles:
            print(" " * 8 + p)


# top level help
def pmbuild_help(config):
    util.print_header("pmbuild version 4.0 -help ")
    print("\nusage:")
    print("    pmbuild <profile> <tasks...>")
    print("    pmbuild make <target> <args...>")
    print("    pmbuild launch <target> <args...>")
    print("\nhelp:")
    print("    pbmuild -help (display this dialog).")
    print("    pbmuild <profile> -help (display help for the chosen profile).")
    print("    pbmuild <profile> <tasks...> -help (display help for the chosen tasks).")
    print("    pbmuild make <profile> -help (display help for the chosen make toolchain + list build targets).")
    print("\noptions:")
    print("    -all (build all tasks).")
    print("    -<task> (build specified tasks by name or by type).")
    print("    -n<task> (exclude specified tasks).")
    print("    -cfg (print jsn config for current profile).")
    print("    -verbose (print more).")
    print("    -ignore_errors (will not exit on error).")
    print("    -args (anything supplied after -args will be forwarded to tools and other scripts).")
    print("\nsettings:")
    print("    pmbuild -credentials (creates a jsn file to allow input and encryption of user names and passwords).")
    print_profiles(config)


# profile help
def pmbuild_profile_help(config, build_order):
    util.print_header("pmbuild version 4.0 -profile help ")
    print("\navailable tasks for profile " + config["user_vars"]["profile"] + ":")
    print("    config.jsn (edit task settings or add new ones in here)")
    print("    build order:")
    for task in build_order:
        print(" " * 8 + task)


# build help for core tasks
def core_help(config, taskname, task_type):
    if task_type == "copy" or task_type == "move":
        print("specify pairs of files or directories for copying/moving [src/input, dst/output]\n")
        print("files:[")
        print("    [files/in/directory, copy/to/directory]")
        print("    [files/with/glob/**/*.txt, copy/to/directory]")
        print("]")
        print("exclude files\n")
        print("excludes:[")
        print("    *.DS_Store")
        print("]")
    else:
        print("no help available for this tool.")
        return


# parses commandline args and config settings to generate a list of filtered tasks in order of execution
def generate_build_order(config, config_all, all):
    # filter tasks
    runnable = []
    for task_name in config.keys():
        task = config[task_name]
        if type(task) != dict:
            continue
        non_tasks = ["clean", "make", "launch", "user_vars"]
        if "type" not in task:
            continue
        if task["type"] in non_tasks:
            continue
        if "explicit" in task.keys():
            if task["explicit"] and "-" + task_name not in sys.argv:
                continue
        if "-n" + task_name in sys.argv:
            continue
        if "-" + task_name in sys.argv or "-" + task["type"] in sys.argv or all:
            runnable.append(task_name)
    # sort
    orderer_keys = [
        "pre_build_order",
        "build_order",
        "post_build_order"
    ]
    buckets = {
        orderer_keys[0]: [],
        orderer_keys[1]: [],
        orderer_keys[2]: []
    }
    orderer_tasks = []
    for key in buckets.keys():
        if key in config_all.keys():
            for i in config_all[key]:
                if i in runnable:
                    buckets[key].append(i)
                    orderer_tasks.append(i)
    for task in runnable:
        if task not in orderer_tasks:
            buckets["build_order"].append(task)
    runnable_ordered = []
    for key in orderer_keys:
        for i in buckets[key]:
            runnable_ordered.append(i)
    return runnable_ordered


# main function
def main():
    start_time = time.time()

    config_file = "config.jsn"
    if os.path.exists("config2.jsn"):
        config_file = "config2.jsn"

    # must have config.json in working directory
    if not os.path.exists(config_file):
        print("[error] no config.jsn in current directory.")
        sys.exit(1)

    # load jsn, inherit etc
    config_all = jsn.loads(open(config_file, "r").read())

    # special args passed from user
    special_args = [
        "-credentials",
        "-help",
        "-verbose",
        "-dry",
        "-silent",
        "-cfg",
        "-clean",
        "-all",
        "-ignore_errors"
    ]

    # switch between different modes
    build_mode = "pmbuild (v4)"
    profile_pos = 1
    if sys.argv[1] == "make" or sys.argv[1] == "launch":
        build_mode = "pmbuild " + sys.argv[1]
        profile_pos = 2

    # add implicit all
    implicit_all = False
    if len(sys.argv) == 2 and profile_pos == 1:
        implicit_all = True

    # extract extra -args
    user_args = []
    if "-args" in sys.argv:
        index = sys.argv.index("-args")
        for i in range(index+1, len(sys.argv)):
            user_args.append(sys.argv[i])
        sys.argv = sys.argv[:index]

    for arg in reversed(special_args):
        if arg not in sys.argv:
            special_args.remove(arg)
        else:
            sys.argv.remove(arg)

    if implicit_all:
        special_args.append("-all")

    # special modes
    if "-credentials" in special_args:
        edit_credentials()
        return

    util.print_header(build_mode)
        
    # first arg is build profile, load profile and merge the config for platform
    profile = ""
    if profile_pos < len(sys.argv):
        if sys.argv[profile_pos] not in config_all:
            print("[error] " + sys.argv[profile_pos] + " is not a valid pmbuild profile")
            print_profiles(config_all)
            sys.exit(1)
        profile = sys.argv[profile_pos]
        config = config_all[sys.argv[profile_pos]]
    else:
        config = config_all

    # print pmbuild top level help
    if "-help" in special_args and len(sys.argv) == 1:
        pmbuild_help(config_all)
        sys.exit(0)
    elif "-help" in special_args and len(sys.argv) == 2 and ("make" in sys.argv or "launch" in sys.argv):
        pmbuild_help(config_all)
        sys.exit(0)

    # check special command modes
    command_mode = ["make", "launch"]
    for cm in command_mode:
        if cm in sys.argv:
            if cm not in config.keys():
                print("[error] " + cm + " is not configured in config.jsn (" + profile + ")")
                error_exit(config)

    # load config user for user specific values (sdk version, vcvarsall.bat etc.)
    configure_user(config, sys.argv)

    # inserts profile
    if "user_vars" not in config.keys():
        config["user_vars"] = dict()
    
    # final handling of invalid profiles
    if profile_pos < len(sys.argv):
        config["user_vars"]["profile"] = sys.argv[profile_pos]
    else:
        print("[error] missing valid pmbuild profile as first positional argument")
        print_profiles(config_all)
        sys.exit(1)

    # inject task keys, to allow alias jobs and multiple runs of the same thing
    for task_name in config.keys():
        task = config[task_name]
        if "type" not in task.keys():
            config[task_name]["type"] = task_name

    config["special_args"] = special_args
    config["user_args"] =  user_args

    # verbosity indicator
    util.log_lvl("pmbuild verbose:", config, "-verbose")

    # obtain tools for this platform
    config["tools"] = dict()
    if "tools" in config_all.keys():
        config["tools"] = config_all["tools"]
    config["tools_help"] = dict()
    if "tools_help" in config_all.keys():
        config["tools_help"] = config_all["tools_help"]
    if "-cfg" in special_args:
        print(sys.argv)
        print(special_args)
        print(json.dumps(config, indent=4))

    # core scripts
    scripts = {
        "copy": copy,
        "move": move,
        "connect": connect,
        "make": make,
        "launch": launch,
        "shell": shell,
        "zip": zip,
        "pmbuild_config": generate_pmbuild_config,
        "vscode": vscode_build
    }

    if sys.argv[1] == "make":
        mf = get_task_files(config, "make")
        make(config, mf, sys.argv[3:])
    elif sys.argv[1] == "launch":
        mf = get_task_files(config, "launch")
        launch(config, mf, sys.argv[3:])
    else:
        # add extensions
        if "extensions" in config_all.keys():
            for ext_name in config_all["extensions"].keys():
                ext = config_all["extensions"][ext_name]
                if "search_path" in ext.keys():
                    sys.path.append(ext["search_path"])
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

        runnable_ordered = generate_build_order(config, config_all, "-all" in special_args)

        # profile pmbuild help
        if "-help" in special_args and len(runnable_ordered) == 0:
            runnable_ordered = generate_build_order(config, config_all, all)
            pmbuild_profile_help(config, runnable_ordered)
            sys.exit(0)

        # run tasks
        for task_name in runnable_ordered:
            task = config[task_name]
            if "type" not in task:
                continue
            if "type" == "clean":
                continue
            util.print_header(task_name)
            task_type = task["type"]
            if task_type in config["tools"].keys():
                if "-help" in special_args:
                    run_tool_help(config, task_name, task_type)
                    continue
                if "files" in task.keys():
                    run_tool(config, task_name, task_type, get_task_files(config, task_name))
                else:
                    run_tool(config, task_name, task_type, [("", "")])
            elif task_type in scripts.keys():
                if "-help" in special_args:
                    core_help(config, task_name, task_type)
                    continue
                if "files" in task.keys():
                    scripts.get(task_type)(config, task_name, get_task_files(config, task_name))
                else:
                    scripts.get(task_type)(config, task_name)
                pass

    util.print_duration(start_time)


# entry point of pmbuild
if __name__ == "__main__":
    main()
