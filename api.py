import time
import struct
import lz4.block
from define import OS
import requests


class FRIDA:
    def __init__(self, frida_api, config):
        self.frida_api = frida_api
        self.config = config
        self.custom_read_memory = config["extended_function"]["custom_read_memory"]
        self.target_os = config["general"]["target_os"]

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
            if ret:
                ret = self.decompress_lz4(ret)
        return ret

    def virtualqueryexfull(self, protect):
        return self.frida_api.VirtualQueryExFull(protect)

    def getmodule(self, name):
        return self.frida_api.GetModule(name)

    def getsymbol(self, address):
        return self.frida_api.GetSymbol(address)

    def memoryscan(self, start, size, bytecode):
        return self.frida_api.MemoryScan(start, size, bytecode)

    def memoryfilter(self, addresses):
        return self.frida_api.MemoryFilter(addresses)

    def enummodules(self):
        return self.frida_api.EnumModules()

    def enumranges(self):
        return self.frida_api.EnumRanges()


class MEMORY_SERVER(FRIDA):
    def __init__(self, frida_api, config):
        super().__init__(frida_api, config)
        self.base_url = "http://" + config["ipconfig"]["memory_server_ip"]
        self.frida_api = frida_api
        self.pid = self.frida_api.GetInfo()["pid"]
        self.openprocess(self.pid)

    def openprocess(self, pid):
        open_process_url = f"{self.base_url}/openprocess"
        open_process_payload = {"pid": pid}
        open_process_response = requests.post(
            open_process_url, json=open_process_payload, proxies={}
        )

        if open_process_response.status_code == 200:
            print(f"Process {pid} opened successfully")
            return True
        else:
            print(
                f"Failed to open process {pid}:{open_process_response.content.decode()}"
            )
            return False

    def readprocessmemory(self, address, size):
        read_memory_url = f"{self.base_url}/readmemory"
        params = {"address": address, "size": size}

        read_memory_response = requests.post(read_memory_url, params=params)

        if read_memory_response.status_code == 200:
            result = read_memory_response.content
            return result
        else:
            print(f"Memory read failed:{read_memory_response.content.decode()}")
            return False

    def memoryscan(
        self,
        pattern,
        address_ranges,
        scan_type,
        scan_id,
        return_as_json=False,
    ):
        memory_scan_url = f"{self.base_url}/memoryscan"
        memory_scan_payload = {
            "pattern": pattern,
            "address_ranges": address_ranges,
            "scan_type": scan_type,
            "scan_id": scan_id,
            "return_as_json": return_as_json,
        }

        start = time.time()
        memory_scan_response = requests.post(memory_scan_url, json=memory_scan_payload)
        end = time.time()
        network_time = end - start

        if memory_scan_response.status_code == 200:
            result = memory_scan_response.json()
            print(f"Pattern found {result['found']} times")
            print(f"Network time: {network_time}")
            return result
        else:
            print(f"Memory scan failed:{memory_scan_response.content.decode()}")
            return False

    def memoryfilter(
        self, pattern, scan_type, scan_id, filter_method, return_as_json=False
    ):
        memory_filter_url = f"{self.base_url}/memoryfilter"
        memory_filter_payload = {
            "pattern": pattern,
            "scan_type": scan_type,
            "scan_id": scan_id,
            "filter_method": filter_method,
            "return_as_json": return_as_json,
        }

        start = time.time()
        memory_filter_response = requests.post(
            memory_filter_url, json=memory_filter_payload
        )
        end = time.time()
        network_time = end - start

        if memory_filter_response.status_code == 200:
            result = memory_filter_response.json()
            print(f"Pattern found {result['found']} times")
            print(f"Network time: {network_time}")
            return result
        else:
            print(f"Memory filter failed:{memory_filter_response.content.decode()}")
            return False
