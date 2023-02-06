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
import api
import util


class Scanner:
    def __init__(self, frida_api, config):
        self.frida_api = frida_api
        self.medit_api = api.MEDITAPI(frida_api, config)
        self.custom_read_memory = config["extended_function"]["custom_read_memory"]
        self.addresses = []
        self.address_list = []
        self.rpm_max_size = 524288 * 128
        self.scan_type = ""
        self.scan_value = None

    def find(self, value, _type):
        self.scan_value = value
        self.scan_type = _type
        self.addresses = []
        self.address_list = []
        regions = self.frida_api.VirtualQueryExFull()
        regions_size = sum([region[1] for region in regions])
        readed_size = 0
        with tqdm(total=regions_size, desc="progress") as bar:
            for i, region in enumerate(regions):
                start = region[0]
                size = region[1]
                tmp = start
                remain_size = size
                ret = b""
                if self.custom_read_memory or _type == "regex":
                    while remain_size > 0:
                        read_size = min(remain_size, self.rpm_max_size)
                        result = self.medit_api.readprocessmemory(tmp, read_size)
                        if result != False:
                            ret = result
                            if _type != "regex":
                                sp = util.StructPack(value, _type)
                                bytecode = sp.pack()
                                bytecode = re.escape(bytecode)
                            elif _type == "regex":
                                bytecode = value.encode()
                            for match in re.finditer(bytecode, ret):
                                self.addresses.append(tmp + match.start())
                                self.address_list.append(
                                    {
                                        "address": tmp + match.start(),
                                        "size": len(match.group(0)),
                                    }
                                )
                        tmp += read_size
                        readed_size += read_size
                        remain_size -= read_size
                        bar.update(read_size)
                else:
                    sp = util.StructPack(value, _type)
                    bytecode = sp.pack()
                    addresses = self.medit_api.memoryscan(start, size, bytecode)
                    if addresses != None:
                        for address in addresses:
                            ad = int(address["address"], 16)
                            sz = address["size"]
                            self.addresses.append(ad)
                            self.address_list.append({"address": ad, "size": sz})
                    bar.update(size)

    def filter(self, value):
        # todo:
        _type = self.scan_type
        filtered_list = []
        regions = self.medit_api.virtualqueryexfull()
        regions_size = sum([region[1] for region in regions])
        readed_size = 0
        with tqdm(total=regions_size, desc="progress") as bar:
            for i, region in enumerate(regions):
                start = region[0]
                size = region[1]
                tmp = start
                remain_size = size
                ret = b""
                if self.custom_read_memory or _type == "regex":
                    while remain_size > 0:
                        read_size = min(remain_size, self.rpm_max_size)
                        result = self.medit_api.readprocessmemory(tmp, read_size)
                        if result != False:
                            ret = result
                            if _type != "regex":
                                sp = util.StructPack(value, _type)
                                bytecode = sp.pack()
                                bytecode = re.escape(bytecode)
                            elif _type == "regex":
                                bytecode = value.encode()
                            for match in re.finditer(bytecode, ret):
                                address = tmp + match.start()
                                if address in self.addresses:
                                    filtered_list.append(
                                        {
                                            "address": address,
                                            "size": len(match.group(0)),
                                        }
                                    )
                        tmp += read_size
                        readed_size += read_size
                        remain_size -= read_size
                        bar.update(read_size)
                else:
                    sp = util.StructPack(value, _type)
                    bytecode = sp.pack()
                    addresses = self.medit_api.memoryscan(start, size, bytecode)
                    if addresses != None:
                        for address in addresses:
                            ad = int(address["address"], 16)
                            if ad in self.addresses:
                                filtered_list.append({"address": ad, "size": size})
                    bar.update(size)
        self.address_list = filtered_list
