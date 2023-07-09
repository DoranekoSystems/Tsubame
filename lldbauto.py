import socket
import os
import sys
import re
import time
import threading
import struct
import queue
from define import OS


class LLDBAutomation:
    def __init__(self, server_ip, server_port, config):
        self.ip = server_ip
        self.lldb_server_port = server_port
        self.config = config
        self.targetos = config["general"]["targetOS"]
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((server_ip, server_port))
        self.s.send(b"+")
        self.disable_ack()
        self.debug_event = [queue.Queue() for i in range(4)]
        self.register_info = []
        self.wp_info_list = [
            {
                "address": 0,
                "bpsize": 0,
                "type": 0,
                "switch": False,
                "enabled": False,
            }
            for i in range(4)
        ]
        self.set_wp_count = 0
        self.lock = threading.Lock()
        self.add_note = None

    def disable_ack(self):
        self.s.send(b"$QStartNoAckMode#b0")
        self.s.recv(1)
        self.s.recv(4096)
        self.s.send(b"+")

    def calc_checksum(self, message):
        sum = 0
        for c in message:
            sum += ord(c)
        sum = sum % 256
        return f"{sum:02x}"

    def send_message(self, message, recvflag=True):
        m = "$" + message + "#" + self.calc_checksum(message)
        self.s.send(m.encode())
        if recvflag:
            result = self.s.recv(4096)
            # ignore $***#hh
            return result[1:-3]

    def attach(self, pid):
        result = self.send_message(f"vAttach;{pid:02x}")
        self.attach_pid = pid
        return result

    def cont(self):
        result = self.send_message("c")
        return result

    def cont2(self, signal, thread):
        result = self.send_message(f"vCont;C{signal:02x}:{thread:02x};c")
        return result

    def step(self, thread):
        result = self.send_message(f"vCont;s:{thread:02x}")
        return result

    def readmem(self, address, size):
        result = self.send_message(f"x{address:02x},{size}")
        return result

    def get_register_info(self, thread):
        message = self.send_message(f"g;thread:{thread}").decode()
        encode_message = ""
        flag = False
        for i in range(len(message)):
            if message[i] == "*" and not flag:
                flag = True
                encode_message += message[i - 1] * (ord(message[i + 1]) - 29)
            else:
                if not flag:
                    encode_message += message[i]
                else:
                    flag = False
        return encode_message

    # 2:write 3:read 4:access
    def set_watchpoint(self, address, size, _type):
        command = ""
        if _type == "w":
            command = "Z2"
        elif _type == "r":
            command = "Z3"
        elif _type == "a":
            command = "Z4"
        result = self.send_message(f"{command},{address:02x},{size}")
        if result == b"OK":
            return True
        else:
            # Already set breakpoint
            if result == b"E09":
                return True
            else:
                return False

    def remove_watchpoint(self, address, size, _type):
        command = ""
        if _type == "w":
            command = "z2"
        elif _type == "r":
            command = "z3"
        elif _type == "a":
            command = "z4"
        result = self.send_message(f"{command},{address:02x},{size}")
        if result == b"OK":
            return True
        else:
            # Already remove breakpoint
            if result == b"E08":
                return True
            elif result == b"":
                return True
            else:
                return False

    def parse_result(self, result):
        _dict = {}
        for r in result.decode().split(";"):
            if r.find(":") != -1:
                key, value = r.split(":")
                if key == "medata" and key in _dict:
                    if int(value, 16) > int(_dict[key], 16):
                        _dict[key] = value
                else:
                    _dict[key] = value
        return _dict

    def interrupt(self):
        self.send_message("\x03", False)

    def interrupt_func(self):
        while True:
            self.lock.acquire()
            if (
                len(
                    [
                        wp
                        for wp in self.wp_info_list
                        if (wp["switch"] == True and wp["enabled"] == False)
                        or (wp["switch"] == False and wp["enabled"] == True)
                    ]
                )
                > 0
            ):
                self.interrupt()
            self.lock.release()
            time.sleep(0.25)

    def debugger_thread(self):
        signal = -1
        thread = -1
        is_debugserver = self.targetos in [OS.IOS.value, OS.MAC.value]
        while True:
            if is_debugserver:
                result = self.cont()
            else:
                # first
                if signal == -1:
                    result = self.cont()
                else:
                    result = self.cont2(signal, thread)
            self.lock.acquire()
            info = self.parse_result(result)
            if is_debugserver:
                if "metype" not in info:
                    self.add_note("Debugger Thread:info is empty.")
                    self.lock.release()
                    continue
                metype = info["metype"]
            else:
                if "thread" not in info:
                    self.add_note("Debugger Thread:info is empty.")
                    self.lock.release()
                    continue
                thread = int(info["thread"], 16)
                signal = int([x for x in info.keys() if x.find("T") == 0][0][1:3], 16)
                if signal == 2 or signal == 5:
                    signal = 0
                # watchpoint
                if len([x for x in info.keys() if x.find("watch") != -1]) > 0:
                    metype = "6"
                else:
                    metype = "5"

            # Breadkpoint Exception
            if metype == "6":
                if is_debugserver:
                    medata = int(info["medata"], 16)
                else:
                    # example: 'T05watch': '0*"7fe22293dc'
                    medata = int(
                        [info[x] for x in info.keys() if x.find("watch") != -1][
                            0
                        ].split('"')[1],
                        16,
                    )
                if medata > 0x100000:
                    threadid = int(
                        [info[x] for x in info.keys() if x.find("thread") != -1][0], 16
                    )

                    if is_debugserver:
                        result = self.step(threadid)
                    else:
                        wp = [
                            wp for wp in self.wp_info_list if wp["address"] == medata
                        ][0]
                        ret1 = self.remove_watchpoint(medata, wp["bpsize"], wp["type"])
                        ret2 = self.step(threadid)
                        ret3 = self.set_watchpoint(medata, wp["bpsize"], wp["type"])

                    if not is_debugserver:
                        registers = self.get_register_info(threadid)

                    register_list = []
                    for i in range(34):
                        if is_debugserver:
                            try:
                                if i == 33:
                                    address = struct.unpack(
                                        "<I", bytes.fromhex(info[f"{i:02x}"])
                                    )[0]
                                else:
                                    address = struct.unpack(
                                        "<Q", bytes.fromhex(info[f"{i:02x}"])
                                    )[0]

                            except Exception as e:
                                address = 0
                        else:
                            try:
                                string = registers[i * 16 : i * 16 + 16]
                                address = struct.unpack("<Q", bytes.fromhex(string))[0]
                                if i == 32:
                                    address -= 4
                            except Exception as e:
                                address = 0
                        register_list.append(address)

                    for i in range(4):
                        self.debug_event[i].put(
                            {
                                "debugevent": 5,
                                "threadid": threadid,
                                "address": medata,
                                "register": register_list,
                            }
                        )

            if metype == "5" or metype == "6":
                threadid = int(
                    [info[x] for x in info.keys() if x.find("thread") != -1][0], 16
                )
                # set watchpoint
                for i in range(4):
                    wp = self.wp_info_list[i]
                    if wp["switch"] == True and wp["enabled"] == False:
                        address = wp["address"]
                        size = wp["bpsize"]
                        _type = wp["type"]
                        self.add_note(
                            f"SetWatchpoint:Address:0x{address:02x},Size:{size},Type:{_type}"
                        )
                        ret = self.set_watchpoint(address, size, _type)
                        self.add_note(f"Result:{ret}")
                        if ret:
                            self.wp_info_list[i]["enabled"] = True

                # remove watchpoint
                for i in range(4):
                    wp = self.wp_info_list[i]
                    if wp["switch"] == False and wp["enabled"] == True:
                        address = wp["address"]
                        size = wp["bpsize"]
                        _type = wp["type"]
                        self.add_note(
                            f"RemoveWatchpoint:Address:0x{address:02x},Size:{size},Type:{_type}"
                        )
                        ret = self.remove_watchpoint(address, size, _type)
                        self.add_note(f"Result:{ret}")
                        if ret:
                            self.wp_info_list[i]["enabled"] = False

            self.lock.release()
