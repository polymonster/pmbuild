import json


def ext_test_function(config, task_name):
    print("extention testing!!")
    print(json.dumps(config[task_name]))


if __name__ == "__main__":
    print("util")