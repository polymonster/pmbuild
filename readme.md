# pmbuild

A build pipeline for game development, it can be used to orchestrate complex multi platform build piplines to transform data into game ready formats, build code and run tests.

# config.jsn

Configs are written in jsn, a relaxed alternative to json. Define build pipeline stages in a `config.jsn` file. A `profile` groups together `tasks` for a particular platform and we can define `tools` to run for each task.

```c++
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

pmbuild also provides some special `%{variables}` evaluated with percentage sign these are evaulated at runtime and some of them are configurable by the user and stored in `config.user.jsn`.

```
%{vs_latest} = locates the latest installation of visual studio ie (vs2019)
%{windows_sdk_version} = configurable windows sdk version
"%{input_file}" = input file from "files" object
"%{output_file}" = output file from "files" object
"%{teamid}" = apple developer team id
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

# Extensions

You can register and call extension modules written in python:

```
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
