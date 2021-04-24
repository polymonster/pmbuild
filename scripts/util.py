import platform
import os
import shutil
import time


# gets path for a network location based on server and folder, /Volumes/folder (mac) \\192.168.0.1\folder (windows)
def get_platform_network_path(server, folder):
    path_formats = {
        "Darwin": "/Volumes/" + folder,
        "Windows": "\\\\" + server + "\\" + folder,
        "Linux": "/" + folder
    }
    return path_formats[platform.system()]


# gets the platform name running this script as (windows, mac or linux)
def get_platform_name():
    names = {
        "Darwin": "mac",
        "Windows": "windows",
        "Linux": "linux"
    }
    return names[platform.system()]


# get platform name, allowing user override from the commandline
def get_platform_name_args(args):
    for i in range(1, len(args)):
        if "-platform" in args[i]:
            return args[i + 1]
    return get_platform_name()


# replaces / with \ for windows friendly file paths
def correct_path(path):
    if os.name == "nt":
        return path.replace("/", "\\")
    return path


# sanitizes file paths to use the correct os specific separator
def sanitize_file_path(path):
    path = path.replace("/", os.sep)
    path = path.replace("\\", os.sep)
    return path


# gets platform correct extension for executable (.exe = windows, no ext linux/mac)
def get_platform_exe_ext(platform):
    if platform == "win32":
        return ".exe"
    else:
        return ""


# gets platform specific command line syntax to run an exectuable
def get_platform_exe_run(platform):
    if platform == "win32":
        return ""
    else:
        return "./"


# create a new dir if it doesnt already exist and not throw an exception
def create_dir(dst_file):
    dir = os.path.dirname(dst_file)
    if not os.path.exists(dir):
        os.makedirs(dir)


# copy src_file to dst_file creating directory if necessary
def copy_file_create_dir(src_file, dst_file):
    if not os.path.exists(src_file):
        print("[error] " + src_file + " does not exist!", flush=True)
        return False
    try:
        create_dir(dst_file)
        src_file = os.path.normpath(src_file)
        dst_file = os.path.normpath(dst_file)
        shutil.copyfile(src_file, dst_file)
        print("copy " + src_file + " to " + dst_file, flush=True)
        return True
    except Exception as e:
        print("[error] failed to copy " + src_file)
        return False


# copy src_file to dst_file creating directory if necessary only if the src file is newer than dst
def copy_file_create_dir_if_newer(src_file, dst_file):
    if not os.path.exists(src_file):
        print("[error] src_file " + src_file + " does not exist!", flush=True)
        return
    if os.path.exists(dst_file):
        if os.path.getmtime(dst_file) >= os.path.getmtime(src_file):
            print(dst_file + " up-to-date")
            return
    copy_file_create_dir(src_file, dst_file)


# member wise merge 2 dicts, second will overwrite dest
def merge_dicts(dest, second):
    for k, v in second.items():
        if type(v) == dict:
            if k not in dest or type(dest[k]) != dict:
                dest[k] = dict()
            merge_dicts(dest[k], v)
        else:
            dest[k] = v


# change file extension to ext
def change_ext(file, ext):
    return os.path.splitext(file)[0] + ext


# safely returns a dictionary value with a default of the key does not exist
def value_with_default(key, dictionary, default_value):
    if key in dictionary.keys():
        return dictionary[key]
    return default_value


# returns list of files with full file path from recursive directory walk
def walk(directory):
    file_list = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_list.append(sanitize_file_path(os.path.join(root, file)))
    return file_list


# opens a file in text editor for user input
def open_text_editor(file):
    pn = get_platform_name()
    cmd = {
        "mac": "open -a TextEdit",
        "windows": "notepad.exe",
        "linux": "gedit"
    }
    os.system(cmd[pn] + " " + file)
    

# print duration of job, ts is start time
def print_duration(ts):
    millis = int((time.time() - ts) * 1000)
    print("--------------------------------------------------------------------------------", flush=True)
    print("pmbuild: All Jobs Complete (" + str(millis) + "ms)")


# prints a header to clearly separate console output and to make build steps quick to find
def print_header(task_name):
    padding = "-" * (79 - len(task_name))
    print("--------------------------------------------------------------------------------", flush=True)
    print(task_name + " " + padding, flush=True)
    print("--------------------------------------------------------------------------------", flush=True)


# prints a message handling verbose only, or silent modes
def log_lvl(msg, config, verbosity=None):
    special_args = config["special_args"]
    if verbosity:
        if verbosity in special_args:
            print(msg)
            return
        return
    if "-silent" not in special_args:
        print(msg)


if __name__ == "__main__":
    print("util")
