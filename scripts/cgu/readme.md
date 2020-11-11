# cgu

This python library consists of utility functions which are useful for parsing and writing c-style languages for code generation tools. Pythons string api, regex and dictionary make it a perfect language for parsing, contextualising and generating code efficiently.

I have been recently developing a number of tools where code generation has been a very powerful tool to improve efficiency and reduce the need to manually write tiresome boiler-plate code. I ended up duplicating a lot of the functionality in this library so this project has started to become my go-to place for code gen needs.

So far I have been adding features as and when I need them, currently a subset of c/c++ is supported.

## Examples

### Preparing source code for parsing

Before doing any parsing we need to prepare the source code to make life easier.

```python

# first we want to sanitize the source, to make parsing easier.. this will:
# - remove empty lines and separate tokens with a single space 
# - remove comments to eliminate any false parsing which may be inside comments
source = sanitize_source(source)

# from the sanitized source we can extract c/c++ include statements 
includes = find_include_statements(source)

# next we want to remove string literals to avoid any false parsing we may encounter inside a string that is not code but looks like code, this will replace string literals with a placeholder so we can re-insert the string later
strings, source = placeholder_string_literals(source)

```

### Parsing source code

Now with clean source code we can perform some tasks.

``` python

# find all instances of a token within source
token = "int"
token_locations = find_all_tokens(token, source)

# find c/c++ structs which will break them down contextually into a dictionary
structs = find_type_declarations("struct", source)

# find all enums and break them down into a dictionary
enums = find_type_declarations("enum", source)

```

### Results

python dictionary containing information is used so you can easily write code back out or extract information you need.

``` json
{
    "type": "struct",
    "name": "second",
    "qualified_name": "scope::second",
    "declaration": "struct second\n{\n[[attributes]]\nfloat x = 10;\nchar array[100] = {};\nvoid function(int a, int b);\nvoid const_function(int c, int d) const;\nvoid inline_impl()\n{\n}\n}",
    "members": [
        {
            "type": "variable",
            "declaration": "\n[[attributes]]\nfloat x = 10",
            "attributes": "attributes"
        },
        {
            "type": "variable",
            "declaration": "\nchar array[100] = {}",
            "attributes": null
        },
        {
            "type": "function",
            "declaration": "\nvoid function(int a, int b)",
            "attributes": null
        },
        {
            "type": "function",
            "declaration": "\nvoid const_function(int c, int d) const",
            "attributes": null
        }
    ],
    "scope": [
        {
            "type": "namespace",
            "name": "scope"
        }
    ],
    "typedefs": [],
    "attributes": "attributes"
    }
```

### Cleaning up

``` python

# re-insert the string literals we made placeholders earlier
source = replace_placeholder_string_literals(strings, source)

```


