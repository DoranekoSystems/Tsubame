from InquirerPy import prompt
import os
import sys
import time
import re
import struct
from threading import Thread
import subprocess
import platform
import bisect
from sortedcontainers import SortedList
from tqdm import tqdm
import hexdump
import lz4.block
from define import OS, MODE
from colorama import Fore, Back, Style
import api
import util


def add_spaces(s):
    return " ".join([s[i : i + 2] for i in range(0, len(s), 2)])


def index(a, x):
    i = bisect.bisect_left(a, x)
    if i != len(a) and a[i] == x:
        return i
    return -1


def NumbersWithinRange(items, lower, upper):
    start = items.bisect(lower)
    end = items.bisect_right(upper)
    return items[start:end]


class Scanner:
    def __init__(self, frida_api, config, info):
        self.frida_api = frida_api
        self.medit_api = api.MEDITAPI(frida_api, config)
        self.custom_read_memory = config["extended_function"]["custom_read_memory"]
        self.addresses = []
        self.address_list = []
        self.rpm_max_size = 524288
        self.scan_type = ""
        self.scan_value = None
        self.protect = "r--"
        self.start_address = 0
        self.end_address = 0x7FFFFFFFFFFFFFFF
        self.near_front = 0
        self.near_back = 0
        self.arch = info["arch"]

    def find(self, value, _type):
        self.scan_value = value
        self.scan_type = _type
        self.addresses = []
        self.address_list = []
        regions = self.medit_api.virtualqueryexfull(self.protect)
        tmp_regions = []
        for region in regions:
            start_address = max(region[0], self.start_address)
            end_address = min(region[0] + region[1], self.end_address)
            if start_address < end_address:
                size = end_address - start_address + 1
                tmp_regions.append([start_address, size])
        regions = tmp_regions
        regions_size = sum([region[1] for region in regions])
        readed_size = 0
        with tqdm(total=regions_size, desc="progress") as bar:
            for i, region in enumerate(regions):
                start = region[0]
                size = region[1]
                tmp = start
                remain_size = size
                ret = b""
                if _type == "regex":
                    while remain_size > 0:
                        read_size = min(remain_size, self.rpm_max_size)
                        result = self.medit_api.readprocessmemory(tmp, read_size)
                        if result != False:
                            ret = result
                            if _type != "regex":
                                sp = util.StructPack(value, _type, self.arch)
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
                    if _type == "aob":
                        bytecode = add_spaces(value.replace(" ", ""))
                    else:
                        sp = util.StructPack(value, _type, self.arch)
                        bytecode = sp.pack().hex()
                    addresses = self.medit_api.memoryscan(start, size, bytecode)
                    if addresses != None:
                        for address in addresses:
                            ad = int(address["address"], 16)
                            sz = address["size"]
                            self.addresses.append(ad)
                            self.address_list.append({"address": ad, "size": sz})
                    bar.update(size)

    def filter(self, value):
        _type = self.scan_type
        filtered_list = []
        regions = self.medit_api.virtualqueryexfull(self.protect)
        tmp_regions = []
        for region in regions:
            start_address = max(region[0], self.start_address)
            end_address = min(region[0] + region[1], self.end_address)
            if start_address < end_address:
                size = end_address - start_address + 1
                tmp_regions.append([start_address, size])
        regions = tmp_regions
        regions_size = sum([region[1] for region in regions])
        readed_size = 0
        with tqdm(total=regions_size, desc="progress") as bar:
            for i, region in enumerate(regions):
                start = region[0]
                size = region[1]
                tmp = start
                remain_size = size
                ret = b""
                data = SortedList(self.addresses)
                addresses_in_region = NumbersWithinRange(data, start, start + size)
                if len(addresses_in_region) > 0:
                    if _type == "regex":
                        while remain_size > 0:
                            read_size = min(remain_size, self.rpm_max_size)
                            result = self.medit_api.readprocessmemory(tmp, read_size)
                            if result != False:
                                ret = result
                                if _type != "regex":
                                    sp = util.StructPack(value, _type, self.arch)
                                    bytecode = sp.pack()
                                    bytecode = re.escape(bytecode)
                                elif _type == "regex":
                                    bytecode = value.encode()
                                for match in re.finditer(bytecode, ret):
                                    address = tmp + match.start()
                                    if index(addresses_in_region, address) != -1:
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
                        if _type == "aob":
                            bytecode = add_spaces(value.replace(" ", ""))
                            bytecode_size = int((len(bytecode) + 1) / 3)
                        else:
                            sp = util.StructPack(value, _type, self.arch)
                            bytecode = sp.pack().hex().zfill(sp.size() * 2)
                            bytecode_size = int(len(bytecode) / 2)
                        if len(addresses_in_region) < 1000:
                            address_infos = [
                                [x, bytecode_size, bytecode]
                                for x in addresses_in_region
                            ]
                            addresses = self.medit_api.memoryfilter(address_infos)
                        else:
                            addresses = self.medit_api.memoryscan(start, size, bytecode)
                        if addresses != None:
                            r = [
                                {
                                    "address": int(x["address"], 16),
                                    "size": x["size"],
                                }
                                for x in addresses
                                if index(addresses_in_region, int(x["address"], 16))
                                != -1
                            ]
                            if len(r) > 0:
                                filtered_list.extend(r)
                        bar.update(size)
                else:
                    bar.update(size)
        self.address_list = filtered_list
