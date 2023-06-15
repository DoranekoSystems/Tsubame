from InquirerPy import prompt
import os
import sys
import time
import re
import struct
from threading import Thread
import subprocess
import platform
from tqdm import tqdm
import hexdump
import lz4.block
from define import OS, MODE
from colorama import Fore, Back, Style
import argparse
import api
import scanner
import util

sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/memoryview")
from hexview import memory_view_mode

questions = [
    {
        "type": "rawlist",
        "name": "command",
        "message": "Please Input a command.",
        "choices": [
            "find",
            "filter",
            "patch",
            "conf",
            "dump",
            "list",
            "view",
            "exit",
        ],
        "default": None,
    },
    {
        "type": "rawlist",
        "name": "find_data_type",
        "message": "Please Input a data type.",
        "choices": [
            "word",
            "dword",
            "qword",
            "float",
            "double",
            "aob",
            "utf8",
            "regex",
        ],
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
        "type": "input",
        "name": "filter_input_value",
        "message": "Please Input a value.",
        "default": "",
        "when": lambda answers: answers["command"] == "filter",
    },
    {
        "type": "input",
        "name": "patch_input_value",
        "message": "Please Input a value.",
        "default": "",
        "when": lambda answers: answers["command"] == "patch",
    },
    {
        "type": "input",
        "name": "conf_input_value",
        "message": "Please Input a value.",
        "default": "",
        "when": lambda answers: answers["command"] == "conf",
    },
    {
        "type": "input",
        "name": "dump_input_value",
        "message": "Please Input a value.",
        "default": "",
        "when": lambda answers: answers["command"] == "dump",
    },
    {
        "type": "input",
        "name": "view_input_value",
        "message": "Please Input a Address.",
        "default": "",
        "when": lambda answers: answers["command"] == "view",
    },
    {
        "type": "input",
        "name": "disasm_input_value",
        "message": "Please Input a value.",
        "default": "",
        "when": lambda answers: answers["command"] == "disasm",
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

MULTIPLE_WINDOW = False


def exec_command(answers, command, pid, medit_api, scan, info):
    if command == "find":
        types = answers["find_data_type"]
        value = answers["find_input_value"]
        scan.find(value, types)
        print(f"HIT COUNT:{len(scan.address_list)}!!\n")

    elif command == "filter":
        value = answers["filter_input_value"]
        old_size = len(scan.address_list)
        scan.filter(value)
        print(f"FILTERD:{len(scan.address_list)}/{old_size}!!\n")

    elif command == "patch":
        value = answers["patch_input_value"]
        for address_info in scan.address_list:
            _type = scan.scan_type
            sp = util.StructPack(value, _type, info["arch"])
            bytecode = sp.pack()
            medit_api.writeprocessmemory(address_info["address"], bytecode)

    elif command == "conf":
        value = answers["conf_input_value"]
        parser = argparse.ArgumentParser()
        parser.add_argument("-s", "--start")
        parser.add_argument("-e", "--end")
        parser.add_argument("-p", "--protect")
        parser.add_argument("-n", "--nearby")
        args = parser.parse_args(value.split(" "))
        if args.protect != None:
            scan.protect = args.protect
        if args.start != None:
            scan.start_address = int(args.start, 16)
        if args.end != None:
            scan.end_address = int(args.end, 16)
        if args.start != None or args.end != None:
            print(
                f"set search region:{hex(scan.start_address)}-{hex(scan.end_address)}"
            )
        if args.nearby != None:
            scan.near_back, scan.near_front = tuple(
                map(lambda x: int(x, 0), args.nearby.split(","))
            )

    elif command == "dump":
        value = answers["dump_input_value"]
        parser = argparse.ArgumentParser()
        parser.add_argument("-s", "--start")
        parser.add_argument("-e", "--end")
        parser.add_argument("-m", "--module")
        parser.add_argument("-f", "--file")
        args = parser.parse_args(value.split(" "))
        if args.module == None:
            start = int(args.start, 16)
            end = int(args.end, 16)
            size = end - start + 1
            ret = medit_api.readprocessmemory(start, size)
            if ret != False:
                if args.file == None:
                    print(hexdump.hexdump(ret))
                else:
                    with open(args.file, mode="wb") as f:
                        f.write(ret)
        else:
            name = args.module
            ret = medit_api.getmodule(name)
            if ret != False:
                start = ret[1]
                size = ret[2]
                filename = name
                if args.file != None:
                    filename = args.file
                ret = medit_api.readprocessmemory(start, size)
                if ret != False:
                    with open(filename, mode="wb") as f:
                        f.write(ret)
                else:
                    print("read memory error")
            else:
                print("module not found")

    elif command == "list":
        addresses = [x["address"] for x in scan.address_list]
        symbols = medit_api.getsymbol(addresses)
        for i, address_info in enumerate(scan.address_list):
            _type = scan.scan_type
            address = address_info["address"]
            read_size = address_info["size"]
            ret = medit_api.readprocessmemory(address, read_size)
            if ret != False:
                symbol = symbols[i]
                if symbol.find("!") == -1:
                    symbol_str = ""
                else:
                    symbol_str = f"({symbol})"

                value = ""
                if _type != "regex":
                    us = util.StructUnpack(ret, _type, info["arch"])
                    value = us.unpack()
                else:
                    value = ret.decode("utf-8")

                print(Fore.GREEN + f"{i+1}:{hex(address)} {Fore.BLUE}{symbol_str}")
                print(Fore.RESET + str(value))

    elif command == "view":
        address = int(answers["view_input_value"], 16)
        if MULTIPLE_WINDOW:

            def run():
                hostos = platform.system()
                if hostos == "Darwin":
                    from applescript import tell

                    cwd = os.getcwd()
                    pycmd = f"python3 main.py -p {pid} --memoryview {hex(address)}"
                    tell.app("Terminal", 'do script "' + f"cd {cwd};{pycmd}" + '"')
                elif hostos == "Windows":
                    subprocess.call(
                        f"python main.py -p {pid} --memoryview {hex(address)}",
                        creationflags=subprocess.CREATE_NEW_CONSOLE,
                    )
                else:
                    print("Not Support")

            t1 = Thread(target=run)
            t1.start()
        else:
            memory_view_mode(medit_api, address)
    elif command == "disasm":
        value = answers["disasm_input_value"]
        parser = argparse.ArgumentParser()
        parser.add_argument("-s", "--start")
        parser.add_argument("-l", "--length")
        args = parser.parse_args(value.split(" "))
        if args.start != None and args.length != None:
            address = int(args.start, 16)
            size = int(args.length, 16)
            ret = medit_api.readprocessmemory(address, size)
            if ret != False:
                bytecode = ret
                sp = util.StructUnpack(bytecode, "asm", info["arch"], address)
                disasm = sp.unpack()
                addresses = [int(d.split(":")[0], 16) for d in disasm.split("\n")]
                symbols = medit_api.getsymbol(addresses)
                for i, d in enumerate(disasm.split("\n")):
                    address_str, inst_str = d.split(":")
                    print(Fore.GREEN + symbols[i], end=":")
                    print(Fore.RESET + inst_str)
            else:
                print("read memory error")

    elif command == "exit":
        print(Fore.BLACK + "exit.")
        sys.exit(0)
    print("--------------------------------------------------------")


def run_loop(pid, config, frida_api, info):
    scan = scanner.Scanner(frida_api, config)
    medit_api = api.MEDITAPI(frida_api, config)
    import gui

    gui.exec(pid, medit_api, scan, info)
    return
    while True:
        try:
            answers = prompt(questions, style=custom_style)
            command = answers["command"]
            exec_command(answers, command, pid, medit_api, scan, info)
        except KeyboardInterrupt as e:
            print("stopping")
        except Exception as e:
            import traceback

            print(traceback.format_exc())
            print(e)
