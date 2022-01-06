# pmbuild

A build system with a focus toward game development, it can be used to orchestrate multi platform build pipelines to transform source assets (textures, shaders, models) into game ready formats, build code, deploy packages and run tests. pmbuild provides a framework to add new build tasks, integrate your own tools and reduce the amount of 'glue' code required to run various build steps.

It is designed to be run locally to deploy to devkits or build code to run tests from the command line but you can also use pmbuild in CI services to reduce the amount of code required in your CI system and so that local users have the same system to build and test with.

It is not a replacement for msbuild, xcodebuild, cmake or other tools. pmbuild is designed to use other build and pre-build systems and the pmbuild system simply provides tools and infrastructure to help.

Checkout the live demo [video](https://youtu.be/L-wPJXZ_oDA) to see it in action.  

Examples of working [scripts](https://github.com/polymonster/pmtech/blob/master/examples/config.jsn) can be seen in my game engine repository [pmtech](https://github.com/polymonster/pmtech) from which this project originated.

### Supported Platforms
- macOS
- Windows
- Linux

### Supported Build Toolchains
- gmake
- xcodebuild
- msbuild
- emmake

### Built-in Tasks
- copy (copy files from src to dst with single files, folders, globs or regex)
- clean (delete intermediate files)
- dependencies (track modified times, inouts and output to prevent redundant work)
- delete_orphans (deletes files which no longer have a source parent in dependencies)
- connect (smb network connections with credentials)
- zip (zip or unzip files)
- premake (generate visual studio solutions, xcode workspace, makefiles, android studio projects)
- texturec (compress textures, generate mip maps, resize, etc...)
- pmfx (generate hlsl, glsl, metal or spir-v from pmfx shader source)
- jsn (make game configs in jsn and convert to json for later use)
- vscode (generates launch, tasks and workspace for vscode)

### Extendible

Bring your own tools and build scripts and hook them into pmbuild and add custom python modules to call from pmbuild.

# Dependencies

- python3 is the only dependency required
- optional: `pip install cryptography` if you want to use encrypted credentials.

# Cloning

pmbuild requires some submodules so please clone recursively:

```
git clone https://github.com/polymonster/pmbuild.git --recursive
```

When submodules update or new ones are added you can update as follows:

```
git submodule update --init --recursive
```

# Usage

Add the pmbuild repository directory to your path for convenience so you can simply invoke `pmbuild`, otherwise you can locate pmbuild manually and run `<path_to_pmbuild>/pmbuild`.

pmbuild is a CLI there must be a file called config.jsn in the current working directory, this how you describe your build pipelines. Add the pmbuild root directory to your path for convenience: 

```
# runs build tasks
pmbuild <profile> <tasks...>

# builds code with xcodebuild, msbuild, makesfiles + clang... configure your own toolchains
pmbuild make <profile> <args...>

# launch built executables to run tests, pass "all" to run all built exe's in a directory
pmbuild launch <profile> <args...>
```

By default you can run all non-explicit tasks by simply running:

```
# run all tasks
pmbuild <profile>

# equivalent to 
pmbuild <profile> -all
```

You can run a single task or a selection of tasks by passing the task name, or you can supply `-n<task_name>` to exclude a task:

```
# runs 2 tasks
pmbuild mac -premake -texturec

# rus all tasks and excludes copy
pmbuild mac -all -ncopy
```

# Config Files

Configs are written in [jsn](https://github.com/polymonster/jsn). Define build tasks in a `config.jsn` file. A `profile` groups together `tasks` for a particular platform and we can define `tools` to run for each task.

```yaml
{
    tools<mac>: {
        // define paths to tools or scripts
    }
    
    tools<windows>: {
        // define different ones for windows
    }
    
    mac:
    {
        // mac profile builds tasks for mac platform
        // ..
        task: {
            // define tasks to run
        }
    }
}
```

# Help / Display Available Profiles

```
pmbuild -help
usage:
    pmbuild <profile> <tasks...>
    pmbuild make <target> <args...>
    pmbuild launch <target> <args...>

help:
    pbmuild -help (display this dialog).
    pbmuild <profile> -help (display help for the chosen profile).
    pbmuild <profile> <tasks...> -help (display help for the chosen tasks).
    pbmuild make <profile> -help (display help for the chosen make toolchain + list build targets).

options:
    -all (build all tasks).
    -<task> (build specified tasks by name or by type).
    -n<task> (exclude specified tasks).
    -cfg (print jsn config for current profile).
    -verbose (print more).
    -ignore_errors (will not exit on error).
    -vars <string of jsn> (added to user_vars ie. "var_bool: true, var_int: 1, var_obj:{key: value}").
    -args (anything supplied after -args will be forwarded to tools and other scripts).

settings:
    pmbuild -credentials (creates a jsn file to allow input and encryption of user names and passwords).

profiles:
    config.jsn (edit task settings or add profiles in here)
        base
        mac
        mac-gl
        win32
        win32-vulkan
        win32-gl
        ios
        ios-ci
        linux
        linux-vulkan
        web
        android
```

# Display Available Tasks For Profile

```
pmbuild <profile> -help
available tasks for profile mac:
    config.jsn (edit task settings or add new ones in here)
    build order:
        premake
        pmfx
        shared_libs
        render_configs
        base_copy
        texturec
        models
        pmbuild_config
```

# Display Help For Task

```
pmbuild <profile> -<task> -help
```

# Variables and Inheritence

jsn allows inheritance and variables `${variable}` evaluated with dollar sign where variables are defined in the script. This allows sharing and re-use of tasks to make configs more compact.

```yaml
{
    base: {
        jsn_vars: {
            data_dir: ""
        }
    }
    // mac inherits from base and overrides ${data_dir}
    mac(base): {
        jsn_vars: {
            data_dir: "bin/osx/data"
        }
    }
}
```

# Special / User Variables

pmbuild also provides special variables evaluated with percentage sign as so `%{variable_name}` these are evaluated at runtime, configurable per user and stored in `config.user.jsn` in addition to supplying your own user args there are some built in ones as well:

```
%{profile} = current building profile (ie mac, win32, linux etc)
%{cwd} = current working directory
%{input_file} = input file from "files" object
%{output_file} = output file from "files" object
%{export_args} = arguments per file from export.jsn
%{vs_latest} = locates the latest installation of visual studio ie (vs2019)
%{windows_sdk_version} = finds latest windows sdk version
%{teamid} = apple developer team id (will prompt for input if not present)
```

You can also pass `-vars` to pmbuild from the commandline as a string of jsn:

```
pmbuild profile -vars "var_bool: true, var_int: 1, var_string:'test', var_obj:{key: value}"
```

# Copy

You can copy files with a copy task, this is often necessary to move files into a data directory or deploy to a dev kit, simply specify an array of file pairs (source, destination) in a task of type copy. Here you can supply [glob](https://docs.python.org/3/library/glob.html) or [regex](https://docs.python.org/3/library/re.html) to find files, a directory or a single file:

```yaml
// copys from src to dest
copy-base:
{
    type: copy
    files: [
        ["assets/folder", "bin/folder"]
    ]
}

// copies src with a glob to dest folders
copy-wildcards:
{
    type: copy
    files: [
         ["assets/random_files/*.txt", "bin/text_files"]
         ["assets/random_files/*.json", "bin/json_files"]
         // recursive
         ["assets/random_files/**/*.xml", "bin/xml_files"]
    ]
}

// copies with a regex match and an array of regex sub finding files containing "matchfile", changing the output directory and file type
copy-regex:
{
    type: copy
        files: [
        {
            match: '^.+?matchfile\\.(.*)'
            directory: "assets"
            sub: [
                ["assets/regex", "bin/regout"]
                [".txt", ".newext"]
            ]
        }
    ] 
}

// you can change the extension or add a suffix to the output files
copy-change-ext:
{
    files: [
         ["assets/random_files/*.txt", "bin/text_files"]
    ]
    change_ext: ".newext"
}
```
You can also specify `excludes` which is an [fnmatch](https://docs.python.org/3/library/fnmatch.html) to further filter files after they are expanded by directory, regex or glob:

```
texturec: {
    args: [
        "-f %{input_file}"
        "%{export_args}"
        "-o %{output_file}"
    ]
    files: [
        ["assets/source/textures", "${data_dir}/textures"]
    ]
    excludes: [
        "export.jsn"
        "*.txt"
        "*.DS_Store"
        "*.dds"
    ]
}
```

# Clean

Clean out stale data and build from fresh, you can define clean tasks which will delete these directories:

```yaml
clean: {
    directories: [
        "${data_dir}"
        "${build_dir}"
        "${bin_dir}"
        "temp"
    ]
}
```

# Tools

Run your own tools or scripts and feed them files with the `files` objects as described in the copy task. We can register different tools for <mac, windows or linux>.


```yaml
{
    tools<mac>: {
        jsn: "${pmbuild_dir}/scripts/jsn/jsn"
        premake: "${pmbuild_dir}/bin/mac/premake5"
        texturec: "${pmbuild_dir}/bin/mac/texturec"
        pmfx: "python3 ${pmbuild_dir}/scripts/pmfx-shader/build_pmfx.py"
        build_models: "${pmtech_dir}/tools/pmbuild_ext/build_models.py"
        mesh_opt: "${pmtech_dir}/tools/bin/osx/mesh_opt"
    }
    
    // run premake tool with the provided args
    mac:
    {
        premake: {
            args: [
                "xcode4"
                "--renderer=metal"
                "--platform_dir=osx"
            ]
        }
    
        // run texturec tool passing %{input_file}, %{output_file} and %{export_args} driven by files and export.jsn
        texturec: {
            args: [
                "-f %{input_file}"
                "%{export_args}"
                "-o %{output_file}"
            ]
            files: [
                ["assets/textures", "${data_dir}/textures"]
                ["../assets/textures", "${data_dir}/textures"]
            ]
            excludes: [
                "export.jsn"
                "*.txt"
                "*.DS_Store"
                "*.dds"
            ]
            change_ext: ".dds"
            dependencies: true
        }
    
        // pmfx is a python script which runs and is passed args
        pmfx: {
            args: [
                "-shader_platform hlsl"
                "-shader_version 5_0"
                "-i assets/shaders ../assets/shaders"
                "-o bin/win32/data/pmfx/hlsl"
                "-h shader_structs"
                "-t temp/shaders"
                "-source"
            ]
        }
    }
}
```

# Extension Python Modules

You can register and call extension modules written in python, specify a path to the python module directory, the module name (.py file) and a function name to invoke when the build runs:

```yaml
extensions: {
    models: {
        search_path: "${pmtech_dir}/tools/pmbuild_ext"
        module: "pmbuild_ext"
        function: "run_models"
    }
    cr:
    {
        search_path: "${pmtech_dir}/tools/pmbuild_ext"
        module: "pmbuild_ext"
        function: "run_cr"
    }
}
```

# Export Config Files

You can use `export.jsn` files in data directories to specify per directory or per file command line arguments to run. For example when converting textures we may want certain textures to be converted to a different format to others. export.jsn files override each other hierarchically by directory so you can have a single export.jsn at the root of a directory tree.

```yaml
{
    texturec:
    {
        "-t": "RGBA8",
        "--mips": true
    }
}
```

You can specify `rules` which select files and apply different settings. jsn inheritance is used here so you can override or inherit the base settings:

```yaml
{
    texturec:
    {
        "-t": "RGBA8"
        "--mips": true

        rules:
        {
            compess:
            {
                files: [
                    "pbr/*.png",
                ]
                "-t": "BC3"
            }
            normalmap:
            {
                files: [
                    "**/*_normal.*"
                ]
                "--normalmap": true
            }
        }
    }
}
```

# Dependencies

With builds you can choose to output dependency info containing build and file timestamps, the commandline used to build and a list of input and output files used during a build. Add `dependencies: true` to any tool with a `files` object to generate an output `.dep` file for each file that is built, subsequent builds will skip if the dependencies remain up-to-date. Dependency info is output in json and can be used in other tools as well to trigger hot reloading.

```yaml
render_configs: {
    type: jsn
        args: [
            "-i %{input_file} -o %{output_file}"
            "-I ../assets/configs assets/configs",
            ]
        files: [
            ["assets/configs", "${data_dir}/configs"]
            ["../assets/configs", "${data_dir}/configs"]
        ]
        // add dependencies to this task
        dependencies: true
}
```
```json
{
    "cmdline": "../third_party/pmbuild/bin/mac/texturec -f assets/textures/blend_test_fg.png -t RGBA8 --mips -o bin/osx/data/textures/blend_test_fg.dds ",
    "files": {
        "bin/osx/data/textures/blend_test_fg.dds": [
            {
                "name": "/Users/alex.dixon/dev/pmtech/examples/assets/textures/blend_test_fg.png",
                "timestamp": 1575376985.285382,
                "data_file": "data/textures/blend_test_fg.dds"
            }
        ]
    }
}
```


# Containers

Sometimes in source asset data we may have a collection of files in a directory we want to group together to concatonate or merge them... for instance if we have individual images for cubemap faces and we want to pass them to a tool to spit out a single cubemap texture. Specify container and `files` comprised of an array of filenames or globs, these files will be written into a `.container.txt` file you can forward to other tools.

```yaml
{
    // specify files in specific order
    container:
    {
        files: [
            "posx.jpg",
            "negx.jpg",
            "posy.jpg",
            "negy.jpg",
            "posz.jpg",
            "negz.jpg"   
        ]
    }
    
    // adds all jpg files in sorted list
    container:
    {
        files: [
            "*.jpg"
        ]
    }
}
```

# Task Types

Each task has a type, you can define this using the `type` member, if the name of the task is the same as a tool, extension or built in function then the `type` member is implicitly added.

```yaml
copy:
{
    files: [
    	// ..
    ]
}

copy-second:
{
    // needs to know the type
    type: copy
    files: [
        // ..
    ]
}
```

# Make

Make is a special command which is specified before the profile

```
pmbuild make <profile> <target>
```

It configures the current environment to build for a specified toolchain and directory, again this uses a `files` object to feed files to the build tool. you can supply a project / make file target name or supply all to build all the projects found by files. This is useful for deploying tests and samples.

```yaml
make: {
    toolchain: "msbuild"
        files: [
            "build/win32/*.vcxproj"
        ]
}
```

# Launch

Launch is a special command like make which can be invoked as follows:

```
pmbuild launch <profile> <target>
```

You can launch built executables from the commandline for running tests, again a files object is used to find the exectuables:

```yaml
launch: {
    cmd: "%{target_path}"
        files: [
            "bin/win32/*.exe"
        ]
}
```

# Network Connections / Credentials

In a development environment we may need to synchronise large amounts of data which is stored on a server, or we may need to build artifacts to a server or deploy to a dev kit. we can mount connections to local area network connections via smb. You can supply credentials for the network connects in plain text, or encrypt them with cryptographic quality encryption to be stored and accessed with a password.

To use encrypted credentials you need to install the python cryptography module:

```
pip install cryptography
```

Then define connections supplying server address, folder to mount and credentials or user/password:

```yaml
// plain text
connect-server:
{
    type: connect
    address: "192.168.0.1" // address or name
    mount: "game_data" // folder to mount
    user: "username",
    password: "pa$$word"
}

// encrypted credentials
connect-server:
{
    type: connect
    address: "192.168.0.1" // address or name
    mount: "game_data" // folder to mount
    credentials: "username",
}
```

To add to the credentials file run:

```
pmbuild -credentials
```

A file `credentials.unlocked.jsn` will be generated in the current working directory for you to edit and add credentials to in the form:

```yaml
{
    username: "password"
}
```

# Explicit Tasks

Tasks can be marked as explicit so that you must specify `-<task_name>` from the commandline and they do not get included automatically with `-all`. This is useful if you have build tasks which you may only need to run infrequently and take a long time to complete. Building third party libraries which are updated infrequently is an example where this can be useful:

```yaml
libs: {
    type: shell
        explicit: true
            commands: [
                "cd ../third_party && ../pmbuild bullet-ios"
                "cd ../third_party && ../pmbuild make bullet-ios all -destination generic/platform=iOS -configuration Release -quiet"
                "cd ../third_party && ../pmbuild make bullet-ios all -destination generic/platform=iOS -configuration Debug -quiet"
            ]
    }
}
```

# Hidden Profiles and Tasks

Tasks and profiles which are marked hidden will not be included in the list returned by `pmbuild -help`. The behaviour of the task or profile is not otherwise affected in any way. This is useful for streamlining the list of commands displayed to the user, or for excluding tasks/profiles which are never called explicitly (e.g. ones that are solely used as a base for inheritance). In the example below, setting the base task `copy_videos_base` to hidden and explicit makes it impossible for a user to call this generic version. 

```yaml
copy_base: 
{
    hidden: true
    explicit: true
    type: copy
    files: [
        ["src_dir/*", "dst_dir"]
    ]
}

copy_mp4_files(copy_base): 
{
    hidden: false
    explicit: false
    files: [
        ["src_dir/*.mp4", "dst_dir"]
    ]
}

```

# Enable/Disable Tasks

Individual tasks in a given profile can be enabled/disabled by setting `enable: true` or `enable: false`. Tasks default to being enabled, and the enabled value is inherited across profiles. This makes it possible to inherit from a profile and make only certain tasks enabled or disabled. In the example below, `child_profile` would run `task_1` and `task_2`, whereas `base_profile` only runs `task_2`.

```yaml
base_profile:
{
    task_1: 
    {
        enabled: false
        type: copy
        files: [
            ["src_dir/*", "dst_dir"]
        ]
    }
    
    task_2:
    {
        ...
    }
}

child_profile(base_profile):
{
    task_1: 
    {
        enabled: true
    }
}


```

# Build Order

By default tasks are built in the order they are specified in the config.jsn files. When using jsn inheritance it may not be clear what the build order might be or you may want to specify an explicit build order. You can do this using the `build_order` lists.

```yaml
pre_build_order: [
    "first task"
]

build_order: [
    "second task"
    // unspecificed tasks are appended here
    // ..
]

post_build_order" [
    "final task"
]
```

Each of the build order lists is optional. If you do not specify a task name in any of the build order lists it will be appended to the `build_order` list.

# vscode

pmbuild can generate `launch.json`, `tasks.json` and `.code-workspace` files for vscode which use pmbuild and a configured make toolchain to build code and launch the exectuable for debugging.

```yaml
vscode: {
    // feed files, here we use xcodeproj but you could locate vcxproj or makefiles
    files: [
        "build/osx/*.xcodeproj"
    ]
    // strip .xcodeproj because we just want the name of the project
    change_ext: ""
    // folders relative to pmbuild cwd will be added to the workspace
    folders: [
        "."
        ".."
    ]
    // array of configurations with pmbuild make, and a launch command, %{target_name} is the basename of the xcodeproj or vcxproj
    configurations:[
        {
            name: "debug"
            make: "../pmbuild make mac %{target_name} -configuration Debug"
            launch: "bin/osx/%{target_name}_d.app/Contents/MacOS/%{target_name}_d"
        }
        {
            name: "release"
            make: "../pmbuild make mac %{target_name} -configuration Release"
            launch: "bin/osx/%{target_name}.app/Contents/MacOS/%{target_name}"
        }
    ]
    debugger: "lldb"
    cwd: "bin/osx"
}
```
You should install the vscode C/C++ extension, install and configure whatever debugger you would like tou use. You can supply different debuggers to the `debugger` member, such as `lldb` (cppdbg) or `gdb` (cppdbg) or `vscode` (cppvsdbg) depending on what you have installed.
