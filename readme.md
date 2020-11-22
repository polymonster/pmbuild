# pmbuild

A build pipeline for game development, it can be used to orchestrate multi platform build piplines to transform data into game ready formats, build code, deploy packages and run tests.

### Supported Platforms
- macOS
- Windows
- Linux

### Supported Build Toolchains
- gmake
- xcodebuild
- msbuild
- emmake

# Usage

There must be a file called config.jsn in the current working directory, this how you describe your build pipelines.

```
pmbuild <profile> <tasks...>
pmbuild make <profile> <args...>
pmbuild launch <profile> <args...>
```

# config.jsn

Configs are written in jsn, a relaxed alternative to json. Define build pipeline stages in a `config.jsn` file. A `profile` groups together `tasks` for a particular platform and we can define `tools` to run for each task.

```yaml
{
    tools<mac>: {
        // define paths to tools 
    }
    
    tools<windows>: {
        // ..
    }
    
    mac-profile:
    {
        // mac profile builds tasks for mac platform
        // ..
        task: {
            // define tasks to run
        }
    }
}
```

# Display Available Profiles

```
pmbuild -help
usage: pmbuild <profile> <tasks...>

options:
    -help (display this dialog).
    -<task> -help (display task help).
    -cfg (print jsn config for current profile).
    -verbose (print more).

profiles:
    config.jsn (edit task settings in here)
        base
        mac
        mac-gl
        win32
        win32-vulkan
        win32-gl
        ios
        linux
        linux-vulkan
        web
        android
        extensions
        tools
```

# Variables and Inheritence

jsn allows inheritence and variables `${variable}` evaluated with dollar sign where variables are defined in the script. This allows sharing and re-use of tasks to make configs more compact.

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

# Special Variables

pmbuild also provides some special `%{variables}` evaluated with percentage sign these are evaulated at runtime and some of them are configurable by the user and stored in `config.user.jsn` which you wil prompted for when they are required if they cannot be auto located.

```
%{vs_latest} = locates the latest installation of visual studio ie (vs2019)
%{windows_sdk_version} = windows sdk version
%{input_file}" = input file from "files" object
%{output_file}" = output file from "files" object
%{teamid}" = apple developer team id
```

# Copy

You can copy files with a copy task, this is often necessary to move files into a data directory or deploy to a dev kit, simply specify an array of file pairs in a task of type copy, you can supply glob or regex to find files:

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
         ["assets/random_files/*.xml", "bin/xml_files"]
    ]
}
```

# Clean

Clean out stale data and build from fresh, you can define clean tasks which will delete these directories:

```
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

Run your own tools or scripts and feed them files with the `files` objects as described in the copy task. We can register tools for <mac, windows or linux> which is the system which pmbuild is currently running on. We can target other platforms such as playstation, xbox but we still build on a windows machine for instance. pmbuild comes bundled with tools:

- premake (generate visual studio solutions, xcode workspace, makefiles, android studio projects)
- texturec (compress textures, generate mip maps, resize, etc...)
- pmfx (generate hlsl, glsl, metal or spir-v from pmfx shader source)
- jsn (make game configs in jsn and convert to json for later use)


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
```

# export.jsn

You can use export.jsn files in data directories to specify per directory or per file command line arguments to run. For example when converting textures we may want certain textures to be converted to a different format to others. export.jsn files override each other hierarchically by directory so you can have a single export.jsn at the root of a directory tree.

```
{
    texturec:
    {
        "-t": "RGBA8",
        "--mips": true
    }
}
```

You can specify `rules` which select files and apply different settings. jsn inheritence is used here so you can override or inherit the base settings:

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

Output dependency info with build timestamps the commandline used to build and lists of input and output files. Dependency info is in json for use in other tools for triggering hot reloading. Add `dependencies: true` to any tool with a `files` object to generate an output `.dep` file for each file that is built, subsequent builds will skip if the dependencies remain up-to-date.

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

Sometimes in source asset data we may have a collection of files in a directory we want to group together to concatonate or merge them... for instance if we have individual images for cubemap faces and we want to pass them to a tool to spit out a single cubemap texture. Specify container and `files` comprised of an array of filenames or globs, these files will be written into a .txt file you can forward to other tools.

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

# Extensions

You can register and call extension modules written in python:

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

In a development environment we may need to synchronise large amounts of data which is stored on a server, or we may need to build artifacts to a server or deploy to a dev kit. we can mount connections to local area network connections via smb. You can supply credentials for the network connects in plain text, or encrypt them with crytographic quality encryption to be stored and accessed with a password:

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
