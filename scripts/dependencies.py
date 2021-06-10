import os
import shutil
import json
import util
import pmbuild

default_settings = dict()
default_settings["textures_dir"] = "assets/textures/"
default_settings["models_dir"] = "assets/mesh/"

# leagacy pmbuild for pmtech
def delete_orphaned_files(build_dir, platform_data_dir):
    for root, dir, files in os.walk(build_dir):
        for file in files:
            dest_file = os.path.join(root, file)
            if dest_file.find("dependencies.json") != -1:
                depends_file = open(dest_file, "r")
                depends_json = json.loads(depends_file.read())
                depends_file.close()
                for file_dependencies in depends_json["files"]:
                    for key in file_dependencies.keys():
                        for dependency_info in file_dependencies[key]:
                            if not os.path.exists(dependency_info["name"]):
                                del_path = os.path.join(platform_data_dir, key)
                                if os.path.exists(del_path):
                                    os.remove(os.path.join(platform_data_dir, key))
                                    print("deleting " + key + " source file no longer exists", flush=True)
                                    print(del_path)
                                    break


# leagacy pmbuild for pmtech
def get_build_config_setting(dir_name):
    if os.path.exists("build_config.json"):
        build_config_file = open("build_config.json", "r")
        build_config_json = json.loads(build_config_file.read())
        build_config_file.close()
        if dir_name in build_config_json:
            return build_config_json[dir_name]
    return default_settings[dir_name]


# leagacy pmbuild for pmtech
def export_config_merge(master, second):
    for key in master.keys():
        if key in second.keys():
            master[key] = export_config_merge(master[key], second[key])
    for key in second.keys():
        if key not in master.keys():
            master[key] = second[key]
    return master


# leagacy pmbuild for pmtech
def get_export_config(filename):
    export_info = dict()
    rpath = filename.replace(os.getcwd(), "")
    rpath = os.path.normpath(rpath)
    sub_dirs = rpath.split(os.sep)
    full_path = os.getcwd()
    for dir in sub_dirs:
        full_path = os.path.join(full_path, dir)
        dir_export_file = os.path.join(full_path, "_export.json")
        if os.path.exists(dir_export_file):
            file = open(dir_export_file, "r")
            file_json = file.read()
            dir_info = json.loads(file_json)
            export_info = export_config_merge(export_info, dir_info)
    return export_info


# leagacy pmbuild for pmtech
def sanitize_filename(filename):
    sanitized_name = filename.replace("@", ":")
    sanitized_name = sanitized_name.replace('/', os.sep)
    return sanitized_name


# leagacy pmbuild for pmtech
def check_up_to_date(dependencies, dest_file):
    filename = os.path.join(dependencies["dir"], "dependencies.json")
    if not os.path.exists(filename):
        print("depends does not exist")
        return False
    file = open(filename)
    d_str = file.read()
    d_json = json.loads(d_str)
    file_exists = False
    for d in d_json["files"]:
        for key in d.keys():
            dependecy_file = sanitize_filename(key)
            if dest_file == dependecy_file:
                for i in d[key]:
                    file_exists = True
                    sanitized = sanitize_filename(i["name"])
                    if not os.path.exists(sanitized):
                        return False
                    if i["timestamp"] < os.path.getmtime(sanitized):
                        return False
    if not file_exists:
        return False
    return True


def create_info(file):
    file = sanitize_filename(file)
    file = os.path.normpath(os.path.join(os.getcwd(), file))
    modified_time = os.path.getmtime(file)
    return {"name": file, "timestamp": float(modified_time)}


def create_dependency_info(inputs, outputs, cmdline=""):
    info = dict()
    if type(cmdline) == list:     
        info["cmdlines"] = cmdline
    else:
        info["cmdline"] = cmdline
    info["files"] = dict()
    for o in outputs:
        o = os.path.join(os.getcwd(), o)
        info["files"][o] = []
        for i in inputs:
            if not os.path.exists(i):
                continue
            ii = create_info(i)
            ii["data_file"] = o[o.find(os.sep + "data" + os.sep) + 1:]
            info["files"][o].append(ii)
    return info


def create_dependency_single(input, output, cmdline=""):
    info = dict()
    info["cmdline"] = cmdline
    info["files"] = dict()
    o = output
    info["files"][o] = []
    i = input
    ii = create_info(i)
    ii["data_file"] = o[o.find(os.sep + "data" + os.sep) + 1:]
    info["files"][o].append(ii)
    return info


def create_dependency(input, output, cmdline=""):
    info = dict()
    info["cmdline"] = cmdline
    info["files"] = dict()
    o = output
    info["files"][o] = []
    i = input
    ii = create_info(i)
    ii["data_file"] = o[o.find(os.sep + "data" + os.sep) + 1:]
    info["files"][o].append(ii)
    return info


# check depenency is up to date for a single output file, made from 1 or more input files 
def check_up_to_date_single(dest_file, deps):
    dep_filename = util.change_ext(dest_file, ".dep")
    if not os.path.exists(dep_filename):
        print("new file: " + os.path.basename(dest_file), flush=True)
        return False
    if not os.path.exists(dest_file):
        print("new file:" + os.path.basename(dest_file), flush=True)
        return False
    if os.path.isdir(dest_file):
        files = os.listdir(dest_file)
        for f in files:
            j = os.path.join(dest_file, f)
            dep_ts = os.path.getmtime(j)
    else:
        dep_ts = os.path.getmtime(dest_file)
    file = open(dep_filename)
    d_str = file.read()
    d_json = json.loads(d_str)
    # check for changes to cmdline
    if "cmdline" in deps:
        if "cmdline" not in d_json.keys() or deps["cmdline"] != d_json["cmdline"]:
            print(dest_file + " cmdline changed", flush=True)
            return False
    # check multi cmdlines
    if "cmdlines" in deps:
        if "cmdlines" not in d_json.keys():
            return False
        if deps["cmdlines"] != d_json["cmdlines"]:
            return False
    # check for new additions
    dep_files = []
    for output in d_json["files"]:
        for i in d_json["files"][output]:
            dep_files.append(i["name"])
    for output in deps["files"]:
        for i in deps["files"][output]:
            if i["name"] not in dep_files:
                print(os.path.basename(dest_file) + ": has new inputs", flush=True)
                return False
    # check for timestamps on existing
    for d in d_json["files"]:
        dest_file = sanitize_filename(d)
        for input_file in d_json["files"][d]:
            # output file does not exist yet
            if not os.path.exists(dest_file):
                print("new file: " + os.path.basename(dest_file), flush=True)
                return False
            # output file is out of date
            if os.path.getmtime(input_file["name"]) > dep_ts:
                print(os.path.basename(dest_file) + ": is out-of-date.", flush=True)
                return False
    print(os.path.basename(dest_file) + ": up-to-date", flush=True)
    return True


def write_to_file(dependencies):
    dir = dependencies["dir"]
    directory_dependencies = os.path.join(dir, "dependencies.json")
    try:
        output_d = open(directory_dependencies, 'wb+')
        output_d.write(bytes(json.dumps(dependencies, indent=4), 'UTF-8'))
        output_d.close()
    except:
        return


def write_to_file_single(deps, file):
    file = util.change_ext(file, ".dep")
    output_d = open(file, 'wb+')
    output_d.write(bytes(json.dumps(deps, indent=4), 'UTF-8'))
    output_d.close()


# delete single orphan
def delete_orphan(file):
    if os.path.exists(file):
        print("delete orphan file: " + file)
        if os.path.isdir(file):
            shutil.rmtree(file)
        else:
            os.remove(file)


# checks if the source file exists and deletes the transcoded / converted version
def delete_orphans(config, task_name, files):
    perform_delete = util.value_with_default("delete_orphans", config["user_vars"], False)
    for f in files:
        if not os.path.exists(f[0]):
            continue
        d_json = json.loads(open(f[0], "r").read())
        dep_files = d_json["files"]
        del_count = 0
        check_count = 0
        basenames = []
        basename_strip = []
        # check dependencies to see if src files still exist
        for output in dep_files:
            for i in dep_files[output]:
                check_count = check_count + 1
                bn = os.path.basename(i["data_file"])
                basenames.append(bn)
                basename_strip.append(os.path.splitext(bn)[0])
                if not os.path.exists(i["name"]):
                    print("orphan file: " + f[0])
                    if perform_delete:
                        del_count = del_count + 1
                        delete_orphan(output)
        # check files which have may have changed ext and alias the same dep
        dirname = os.path.dirname(f[0])
        dir_list = os.listdir(dirname)
        for ff in dir_list:
            if ff.endswith(".dep"):
                continue
            bn = os.path.basename(ff)
            bns = os.path.splitext(bn)[0]
            if bns in basename_strip:
                if bn not in basenames:
                    print("orphan file dst changed: " + ff + " to " + str(basenames))
                    if perform_delete:
                        delete_orphan(os.path.join(dirname, ff))
        # delete dependency file itself if we remove all outputs
        if del_count == check_count:
            print("delete orphan dep: " + f[0])
            os.remove(f[0])



        
