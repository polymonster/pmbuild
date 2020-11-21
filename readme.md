# pmbuild

A build pipeline for game development, it can be used to orchestrate complex multi platform build piplines to transform data into game ready formats, build code and run tests.

# config.jsn

Define build pipeline stages in a `config.jsn` file. A `profile` groups together `tasks` for a particular platform and we can define `tools` to run for each task.

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

you can copy files with a copy task, this is often necessary to move files into a data directory or deploy to a dev kit, simply specify an array of file pairs in a task of type copy:

```c++
copy-base:
{
    type: copy
    files: [
        ["assets/folder", "bin/folder"]
    ]
}

copy-wildcards:
{
	type: copy
	files: [
		["assets/random_files/*.txt", "bin/text_files"]
		["assets/random_files/*.json", "bin/json_files"]
		["assets/random_files/*.xml", "bin/xml_files"]
	]
}

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
```
