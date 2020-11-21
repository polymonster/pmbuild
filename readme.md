# pmbuild

A build pipeline for game development, it can be used to orchestrate complex multi platform build piplines to transform data into game ready formats, build code and run tests.

It is designed to be used locally as well druven from CI services to transfer data from network locations, transform into game ready formats deploy to devkits or package products for submission.

### supported platforms
- macOS
- Windows
- Linux

### supported build toolchains
- gmake
- xcodebuild
- msbuild
- emmake

# usage

There must be a file called config.jsn in the current working directory.

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

# display available profiles

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

# variables and inheritence

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

# special variables

pmbuild also provides some special `%{variables}` evaluated with percentage sign these are evaulated at runtime and some of them are configurable by the user and stored in `config.user.jsn` which you wil prompted for when they are required if they cannot be auto located.

```
%{vs_latest} = locates the latest installation of visual studio ie (vs2019)
%{windows_sdk_version} = windows sdk version
%{input_file}" = input file from "files" object
%{output_file}" = output file from "files" object
%{teamid}" = apple developer team id
```

# copy

you can copy files with a copy task, this is often necessary to move files into a data directory or deploy to a dev kit, simply specify an array of file pairs in a task of type copy, you can supply glob or regex to find files:

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

# clean

When building transient directories that are not managed inside source control sometimes these directories can become filled with stale data, you can define clean tasks which will delete these directories:

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

# tools

you can run tools and feed them files with the file objects describe in copy. We can register tools for <mac, windows or linux> which is the system which pmbuild is currently running on. We can target other platforms such as playstation, xbox but we still build on a windows machine for instance. pmbuild comes bundled with tools:
- premake (generate visual studio solutions, xcode workspace, makefiles, android studio projects)
- texturec (compress textures, generate mip maps, resize, etc...)
- pmfx (generate hlsl, glsl, metal or spir-v from pmfx shader source)

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

# extensions

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

# task types

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

# make

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

# launch

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

# network connections / credentials

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

```
{
    username: "password"
}
```
