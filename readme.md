# pmbuild

A build pipeline for game development, it can be used to orchestrate complex multi platform build piplines to transform data into game ready formats, build code and run tests.

# config.jsn

Define build pipeline stages in a `config.jsn` file. A `profile` groups together `tasks` for a particular platform and we can define `tools` to run for each task.

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
    
    tools<windows>: {
        // ..
    }
    
    mac:
    {
        // mac profile builds tasks for mac platform
        // ..
    }
}
```
