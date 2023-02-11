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


class MEDITAPI:
    def __init__(self, frida_api, config):
        self.frida_api = frida_api
        self.config = config
        self.custom_read_memory = config["extended_function"]["custom_read_memory"]
        self.target_os = config["general"]["targetOS"]

    def decompress_lz4(self, data):
        # iOS
        if self.custom_read_memory and self.target_os == OS.IOS.value:
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
        elif self.custom_read_memory and self.target_os == OS.ANDROID.value:
            uncompressed_size = struct.unpack("<I", data[-4:])[0]
            decompress_bytes = lz4.block.decompress(data[:-4], uncompressed_size)
            ret = decompress_bytes
            return ret
        else:
            return data

    def writeprocessmemory(self, address, bytecode):
        return self.frida_api.WriteProcessMemory(address, list(bytecode))

    def readprocessmemory(self, address, size):
        if size < 1000:
            ret = self.frida_api.ReadProcessMemory(address, size, False)
        else:
            ret = self.frida_api.ReadProcessMemory(address, size, True)
            if ret != False:
                ret = self.decompress_lz4(ret)
        return ret

    def virtualqueryexfull(self, protect):
        return self.frida_api.VirtualQueryExFull(protect)

    def getmodule(self, name):
        return self.frida_api.GetModule(name)

    def memoryscan(self, start, size, bytecode):
        return self.frida_api.MemoryScan(start, size, bytecode)
