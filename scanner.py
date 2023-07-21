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
import traceback
import api
import util
import asyncio


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
    scan_complete = True
    progress = None
    add_note = None
    datatable = None

    def __init__(self, frida_api, config):
        self.frida_api = frida_api
        self.frida = api.FRIDA(frida_api, config)
        self.custom_read_memory = config["extended_function"]["custom_read_memory"]
        self.addresses = []
        self.address_list = []
        self.rpm_max_size = 524288
        self.scan_type = "int32"
        self.scan_value = None
        self.protect = "rw-"
        self.start_address = 0
        self.end_address = 0x7FFFFFFFFFFFFFFF
        self.near_front = 0
        self.near_back = 0
        self.max_list_num = 10000

    async def find(self, value, _type):
        try:
            self.progress.update(f"find start!")
            await asyncio.sleep(0)
            self.scan_complete = False
            self.scan_value = value
            self.scan_type = _type
            self.addresses = []
            self.address_list = []
            regions = self.frida.virtualqueryexfull(self.protect)
            tmp_regions = []
            self.datatable.clear()
            for region in regions:
                start_address = max(region[0], self.start_address)
                end_address = min(region[0] + region[1], self.end_address)
                if start_address < end_address:
                    size = end_address - start_address + 1
                    tmp_regions.append([start_address, size])
            regions = tmp_regions
            regions_size = sum([region[1] for region in regions])
            readed_size = 0
            for i, region in enumerate(regions):
                await asyncio.sleep(0)
                start = region[0]
                size = region[1]
                tmp = start
                remain_size = size
                ret = b""
                if _type == "regex":
                    while remain_size > 0:
                        read_size = min(remain_size, self.rpm_max_size)
                        result = self.frida.readprocessmemory(tmp, read_size)
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
                                        "value": match.group(0).decode(),
                                    }
                                )
                        tmp += read_size
                        readed_size += read_size
                        remain_size -= read_size
                        self.progress.update(f"{int(readed_size/regions_size*100)}%")
                else:
                    if _type == "aob":
                        bytecode = add_spaces(value.replace(" ", ""))
                    else:
                        sp = util.StructPack(value, _type)
                        bytecode = sp.pack().hex()
                    addresses = self.frida.memoryscan(start, size, bytecode)
                    if addresses != None:
                        for address in addresses:
                            ad = int(address["address"], 16)
                            sz = address["size"]
                            self.addresses.append(ad)
                            self.address_list.append(
                                {"address": ad, "size": sz, "value": value}
                            )
                    readed_size += size
                    self.progress.update(f"{int(readed_size/regions_size*100)}%")
            for i, address in enumerate(self.address_list):
                if i >= self.max_list_num:
                    break
                self.datatable.add_row(
                    *[i + 1, hex(address["address"]), address["value"]]
                )
            self.progress.update(f"complete => founds:{len(self.addresses)}")
            self.scan_complete = True
        except Exception as e:
            self.scan_complete = True
            self.progress.update(f"an error occured")
            self.datatable.clear()
            self.add_note(traceback.format_exc())

    async def filter(self, value):
        try:
            if self.near_back != 0 or self.near_front != 0:
                self.progress.update(f"nearby start!")
            else:
                self.progress.update(f"filter start!")
            await asyncio.sleep(0.05)
            self.scan_complete = False
            _type = self.scan_type
            filterd_list = []
            filterd_addresses = []
            regions = self.frida.virtualqueryexfull(self.protect)
            tmp_regions = []
            self.datatable.clear()
            for region in regions:
                start_address = max(region[0], self.start_address)
                end_address = min(region[0] + region[1], self.end_address)
                if start_address < end_address:
                    size = end_address - start_address + 1
                    tmp_regions.append([start_address, size])
            regions = tmp_regions
            regions_size = sum([region[1] for region in regions])
            readed_size = 0

            # nearby search
            if self.near_back != 0 or self.near_front != 0:
                self.addresses = list(
                    set(
                        [
                            x + n
                            for x in self.addresses
                            for n in range(-1 * self.near_back, self.near_front + 1)
                        ]
                    )
                )

            for i, region in enumerate(regions):
                await asyncio.sleep(0)
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
                            result = self.frida.readprocessmemory(tmp, read_size)
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
                                        filterd_list.append(
                                            {
                                                "address": address,
                                                "size": len(match.group(0)),
                                                "value": match.group(0).decode(),
                                            }
                                        )
                                        filterd_addresses.append(address)
                            tmp += read_size
                            readed_size += read_size
                            remain_size -= read_size
                            self.progress.update(
                                f"{int(readed_size/regions_size*100)}%"
                            )
                    else:
                        if _type == "aob":
                            bytecode = add_spaces(value.replace(" ", ""))
                            bytecode_size = int((len(bytecode) + 1) / 3)
                        else:
                            sp = util.StructPack(value, _type)
                            bytecode = sp.pack().hex().zfill(sp.size() * 2)
                            bytecode_size = int(len(bytecode) / 2)
                        if len(addresses_in_region) < 1000000:
                            address_infos = [
                                [x, bytecode_size, bytecode]
                                for x in addresses_in_region
                            ]
                            addresses = self.frida.memoryfilter(address_infos)
                        else:
                            addresses = self.frida.memoryscan(start, size, bytecode)
                        if addresses != None:
                            r = [
                                {
                                    "address": int(x["address"], 16),
                                    "size": x["size"],
                                    "value": value,
                                }
                                for x in addresses
                                if index(addresses_in_region, int(x["address"], 16))
                                != -1
                            ]
                            if len(r) > 0:
                                filterd_list.extend(r)
                                filterd_addresses.extend([x["address"] for x in r])
                        readed_size += size

                        self.progress.update(f"{int(readed_size/regions_size*100)}%")
                else:
                    readed_size += size
                    self.progress.update(f"{int(readed_size/regions_size*100)}%")
            self.address_list = filterd_list
            self.addresses = filterd_addresses
            for i, address in enumerate(self.address_list):
                if i >= self.max_list_num:
                    break
                self.datatable.add_row(
                    *[i + 1, hex(address["address"]), address["value"]]
                )
            self.progress.update(f"complete => founds:{len(self.addresses)}")
            self.scan_complete = True
        except Exception as e:
            self.scan_complete = True
            self.progress.update(f"an error occured")
            self.datatable.clear()
            self.add_note(traceback.format_exc())


class MSScanner(Scanner):
    def __init__(self, frida_api, config, scan_id):
        super().__init__(frida_api, config)
        self.custom_read_memory = config["extended_function"]["custom_read_memory"]
        self.base_url = config["ipconfig"]["memory_server_ip"]
        self.memory_server = api.MEMORY_SERVER(frida_api, config)
        self.scan_id = scan_id

    async def find(self, value, _type):
        try:
            self.progress.update(f"find start!")
            await asyncio.sleep(0.05)
            self.scan_complete = False
            self.scan_value = value
            self.scan_type = _type
            self.addresses = []
            self.address_list = []
            regions = self.frida.virtualqueryexfull(self.protect)
            address_ranges = []
            self.datatable.clear()
            for region in regions:
                start_address = max(region[0], self.start_address)
                end_address = min(region[0] + region[1], self.end_address)
                if start_address < end_address:
                    address_ranges.append([start_address, end_address])
            if _type == "aob":
                bytecode = value.replace(" ", "")
            elif _type == "regex":
                bytecode = value
            else:
                sp = util.StructPack(value, _type)
                bytecode = sp.pack().hex()
            is_regex = False
            if _type == "regex":
                is_regex = True
            result = self.memory_server.memoryscan(
                bytecode, address_ranges, self.scan_id, is_regex, True
            )
            if result != False:
                for r in result["matched_addresses"]:
                    ad = r["address"]
                    if _type == "regex":
                        v = bytes.fromhex(r["value"]).decode()
                        sz = len(v)
                    else:
                        sz = int(len(r["value"]) / 2)
                        byte_data = bytes.fromhex(r["value"])
                        v = util.StructUnpack(byte_data, _type).unpack()
                    self.addresses.append(ad)
                    self.address_list.append({"address": ad, "size": sz, "value": v})
            else:
                pass
            for i, address in enumerate(self.address_list):
                if i >= self.max_list_num:
                    break
                self.datatable.add_row(
                    *[i + 1, hex(address["address"]), address["value"]]
                )
            self.progress.update(f"complete => founds:{len(self.addresses)}")
            self.scan_complete = True
        except Exception as e:
            self.scan_complete = True
            self.progress.update(f"an error occured")
            self.datatable.clear()
            self.add_note(traceback.format_exc())

    async def filter(self, value):
        try:
            if self.near_back != 0 or self.near_front != 0:
                await super().filter(value)
                return
            else:
                self.progress.update(f"filter start!")
            await asyncio.sleep(0.05)
            self.datatable.clear()

            self.addresses = []
            self.address_list = []
            if self.scan_type == "aob":
                bytecode = value.replace(" ", "")
            elif self.scan_type == "regex":
                bytecode = value
            else:
                sp = util.StructPack(value, self.scan_type)
                bytecode = sp.pack().hex()
            is_regex = False
            if self.scan_type == "regex":
                is_regex = True
            result = self.memory_server.memoryfilter(
                bytecode, self.scan_id, is_regex, True
            )
            if result != False:
                for r in result["matched_addresses"]:
                    ad = r["address"]
                    if self.scan_type == "regex":
                        v = bytes.fromhex(r["value"]).decode()
                        sz = len(v)
                    else:
                        sz = int(len(r["value"]) / 2)
                        byte_data = bytes.fromhex(r["value"])
                        v = util.StructUnpack(byte_data, self.scan_type).unpack()
                    self.addresses.append(ad)
                    self.address_list.append({"address": ad, "size": sz, "value": v})
            else:
                pass
            for i, address in enumerate(self.address_list):
                if i >= self.max_list_num:
                    break
                self.datatable.add_row(
                    *[i + 1, hex(address["address"]), address["value"]]
                )
            self.progress.update(f"complete => founds:{len(self.addresses)}")
            self.scan_complete = True
        except Exception as e:
            self.scan_complete = True
            self.progress.update(f"an error occured")
            self.datatable.clear()
            self.add_note(traceback.format_exc())
