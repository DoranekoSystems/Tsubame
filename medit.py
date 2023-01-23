from InquirerPy import prompt
import os
import sys
import time
import re
import struct
from threading import Thread
import subprocess
from tqdm import tqdm
import hexdump
import lz4.block
from define import OS, MODE
from colorama import Fore, Back, Style

sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/memoryview")
from hexview import memory_view_mode

questions = [
    {
        "type": "rawlist",
        "name": "command",
        "message": "Please Input a command.",
        "choices": ["find", "filter", "patch", "dump", "list", "view", "exit"],
        "default": None,
    },
    {
        "type": "checkbox",
        "name": "find_data_type",
        "message": "Please Input a data type.",
        "choices": ["word", "dword", "qword", "utf8", "utf16", "regex"],
        "default": "dword",
        "when": lambda answers: answers["command"] == "find",
    },
    {
        "type": "input",
        "name": "find_input_value",
        "message": "Please Input a value.",
        "default": "",
        "when": lambda answers: answers["find_data_type"],
    },
    {
        "type": "checkbox",
        "name": "filter_data_type",
        "message": "Please Input a data type.",
        "choices": ["word", "dword", "qword", "utf8", "utf16", "regex"],
        "default": "dword",
        "when": lambda answers: answers["command"] == "filter",
    },
    {
        "type": "input",
        "name": "filter_input_value",
        "message": "Please Input a value.",
        "default": "",
        "when": lambda answers: answers["filter_data_type"],
    },
    {
        "type": "rawlist",
        "name": "patch_data_type",
        "message": "Please Input a data type.",
        "choices": ["word", "dword", "qword", "utf8", "utf16"],
        "default": "dword",
        "when": lambda answers: answers["command"] == "patch",
    },
    {
        "type": "input",
        "name": "patch_input_value",
        "message": "Please Input a value.",
        "default": "",
        "when": lambda answers: answers["patch_data_type"],
    },
    {
        "type": "input",
        "name": "dump_input_value",
        "message": "Please Input a value(start - size).",
        "default": "",
        "when": lambda answers: answers["command"] == "dump",
    },
    {
        "type": "rawlist",
        "name": "list_data_type",
        "message": "Please Input a data type.",
        "choices": ["word", "dword", "qword", "utf8", "utf16", "regex"],
        "default": "dword",
        "when": lambda answers: answers["command"] == "list",
    },
    {
        "type": "input",
        "name": "list_regex_input_value",
        "message": "Please Input a value.",
        "default": "",
        "when": lambda answers: answers["list_data_type"] == "regex",
    },
    {
        "type": "input",
        "name": "view_input_value",
        "message": "Please Input a Address.",
        "default": "",
        "when": lambda answers: answers["command"] == "view",
    },
]


custom_style = {
    "separator": "#cc5454",
    "questionmark": "#673ab7 bold",
    "selected": "#cc5454",  # default
    "pointer": "#673ab7 bold",
    "instruction": "",  # default
    "answer": "#f44336 bold",
    "question": "",
}


ADDRESS_LIST = []
CUSTOM_READ_MEMORY = False
TARGET_OS = None
MULTIPLE_WINDOW = False
API = None
RPM_MAX_SIZE = 524288


def decompress_lz4(data):
    # iOS
    if CUSTOM_READ_MEMORY and TARGET_OS == OS.IOS.value:
        decompress_bytes = b""
        tmp = data
        last_uncompressed = b""
        # todo:bv4-
        while True:
            if (tmp[0:4] != b"bv41") or (tmp[0:4] == b"bv4$"):
                break
            uncompressed_size, compressed_size = struct.unpack("<II", tmp[4:12])
            last_uncompressed = lz4.block.decompress(
                tmp[12 : 12 + compressed_size],
                uncompressed_size,
                dict=last_uncompressed,
            )
            tmp = tmp[12 + compressed_size :]
            decompress_bytes += last_uncompressed
        ret = decompress_bytes
        return ret
    else:
        return data


def readprocessmemory(address, size):
    if size < 1000:
        ret = API.ReadProcessMemory(address, size, False)
    else:
        ret = API.ReadProcessMemory(address, size, True)
        if ret != False:
            ret = decompress_lz4(ret)
    return ret


def run_loop(pid, config, api):
    global ADDRESS_LIST
    global CUSTOM_READ_MEMORY
    global TARGET_OS
    global API
    TARGET_OS = config["general"]["targetOS"]
    CUSTOM_READ_MEMORY = config["extended_function"]["custom_read_memory"]
    MULTIPLE_WINDOW = config["memoryview"]["multiple_window"]
    API = api
    while True:
        answers = prompt(questions, style=custom_style)
        command = answers["command"]
        if command == "find":
            ADDRESS_LIST = []
            input_value = answers["find_input_value"]
            regions = api.VirtualQueryExFull()
            regions_size = sum([region[1] for region in regions])
            readed_size = 0
            with tqdm(total=regions_size, desc="progress") as bar:
                for i, region in enumerate(regions):
                    start = region[0]
                    size = region[1]
                    tmp = start
                    remain_size = size
                    ret = b""
                    data_type = answers["find_data_type"]
                    if len(data_type) > 1 or "regex" in data_type:
                        while remain_size > 0:
                            read_size = min(remain_size, RPM_MAX_SIZE)
                            result = readprocessmemory(tmp, read_size)
                            if result != False:
                                ret = result
                                for _type in data_type:
                                    if _type == "word":
                                        bytecode = struct.pack("<H", int(input_value))
                                        bytecode = re.escape(bytecode)
                                    elif _type == "dword":
                                        bytecode = struct.pack("<I", int(input_value))
                                        bytecode = re.escape(bytecode)
                                    elif _type == "qword":
                                        bytecode = struct.pack("<Q", int(input_value))
                                        bytecode = re.escape(bytecode)
                                    elif _type == "utf8":
                                        bytecode = input_value.encode()
                                        bytecode = re.escape(bytecode)
                                    elif _type == "regex":
                                        bytecode = input_value.encode()
                                    for match in re.finditer(bytecode, ret):
                                        ADDRESS_LIST.append(tmp + match.start())
                            tmp += read_size
                            readed_size += read_size
                            remain_size -= read_size
                            bar.update(read_size)
                    else:
                        _type = data_type[0]
                        if _type == "word":
                            bytecode = struct.pack("<H", int(input_value))
                        elif _type == "dword":
                            bytecode = struct.pack("<I", int(input_value))
                        elif _type == "qword":
                            bytecode = struct.pack("<Q", int(input_value))
                        elif _type == "utf8":
                            bytecode = input_value.encode()
                        addresses = api.MemoryScan(start, size, bytecode.hex())
                        if addresses != None:
                            for address in addresses:
                                ad = int(address["address"], 16)
                                sz = address["size"]
                                ADDRESS_LIST.append(ad)
                        bar.update(size)
            print(f"HIT COUNT:{len(ADDRESS_LIST)}!!\n")

        elif command == "filter":
            data_type = answers["filter_data_type"]
            input_value = answers["filter_input_value"]
            old_size = len(ADDRESS_LIST)
            FILTER_LIST = []
            with tqdm(total=old_size, desc="progress") as bar:
                for address in ADDRESS_LIST:
                    for _type in data_type:
                        read_size = 0
                        if _type == "word":
                            bytecode = struct.pack("<H", int(input_value))
                            bytecode = re.escape(bytecode)
                            read_size = 2
                        elif _type == "dword":
                            bytecode = struct.pack("<I", int(input_value))
                            bytecode = re.escape(bytecode)
                            read_size = 4
                        elif _type == "qword":
                            bytecode = struct.pack("<Q", int(input_value))
                            bytecode = re.escape(bytecode)
                            read_size = 8
                        elif _type == "utf8":
                            bytecode = input_value.encode()
                            bytecode = re.escape(bytecode)
                            read_size = len(bytecode)
                        ret = readprocessmemory(address, read_size)
                        if ret != False:
                            for match in re.finditer(bytecode, ret):
                                FILTER_LIST.append(address)
                    bar.update(1)
            ADDRESS_LIST = FILTER_LIST
            print(f"FILTERD:{len(ADDRESS_LIST)}/{old_size}!!\n")

        elif command == "patch":
            _type = answers["patch_data_type"]
            input_value = answers["patch_input_value"]
            for address in ADDRESS_LIST:
                if _type == "word":
                    bytecode = struct.pack("<H", int(input_value))
                elif _type == "dword":
                    bytecode = struct.pack("<I", int(input_value))
                elif _type == "qword":
                    bytecode = struct.pack("<Q", int(input_value))
                elif _type == "utf8":
                    bytecode = input_value.encode()
                api.WriteProcessMemory(address, list(bytecode))

        elif command == "dump":
            dump_message = answers["dump_input_value"]
            start = int(dump_message.split(" ")[0], 16)
            size = int(dump_message.split(" ")[1])
            ret = readprocessmemory(start, size)
            print(hexdump.hexdump(ret))

        elif command == "list":
            _type = answers["list_data_type"]
            for i, address in enumerate(ADDRESS_LIST):
                if _type == "word":
                    read_size = 2
                elif _type == "dword":
                    read_size = 4
                elif _type == "qword":
                    read_size = 8
                elif _type == "utf8":
                    read_size = 256
                elif _type == "regex":
                    read_size = 256
                ret = readprocessmemory(address, read_size)
                if ret != False:
                    value = ""
                    if _type == "word":
                        value = struct.unpack("<H", ret)[0]
                    elif _type == "dword":
                        value = struct.unpack("<I", ret)[0]
                    elif _type == "qword":
                        value = struct.unpack("<Q", ret)[0]
                    elif _type == "utf8":
                        value = ""
                        for j in range(256):
                            try:
                                value += chr(ret[j])
                            except Exception as e:
                                break
                    elif _type == "regex":
                        input_value = answers["list_regex_input_value"]
                        match = re.match(input_value.encode(), ret)
                        try:
                            value = match.group(0)
                        except Exception as e:
                            pass

                    print(Fore.GREEN + f"{i+1}:{hex(address)}")
                    print(Fore.RESET + str(value))

        elif command == "view":
            address = int(answers["view_input_value"], 16)
            if MULTIPLE_WINDOW:
                def run():
                    subprocess.call(f"python main.py -p {pid} --memoryview {hex(address)}", creationflags=subprocess.CREATE_NEW_CONSOLE)
                t1 = Thread(target=run)
                t1.start()
            else:
                memory_view_mode(api,address)

        elif command == "exit":
            print(Fore.BLACK + "exit.")
            sys.exit(0)
        print("--------------------------------------------------------")
