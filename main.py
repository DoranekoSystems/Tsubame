from InquirerPy import prompt
import frida
import threading
import time
import sys
import toml
from define import OS, MODE
import medit
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/memoryview")
from hexview import memory_view_mode

with open("config.toml") as f:
    config = toml.loads(f.read())


def get_device():
    mgr = frida.get_device_manager()
    changed = threading.Event()

    def on_changed():
        changed.set()

    mgr.on("changed", on_changed)

    device = None
    while device is None:
        devices = [dev for dev in mgr.enumerate_devices() if dev.type == "usb"]
        if len(devices) == 0:
            print("Waiting for usb device...")
            changed.wait()
        else:
            device = devices[0]

    mgr.off("changed", on_changed)
    return device


def main(package, pid=None, run_mode="medit", memoryview_address=None):
    targetOS = config["general"]["targetOS"]
    mode = config["general"]["mode"]
    frida_server_ip = config["ipconfig"]["frida_server_ip"]
    binary_path = config["general"]["binary_path"]

    if targetOS in [OS.ANDROID.value, OS.IOS.value]:
        if frida_server_ip != "":
            device = frida.get_device_manager().add_remote_device(frida_server_ip)
        else:
            device = get_device()
        if pid == None:
            apps = device.enumerate_applications()
            target = package
            for app in apps:
                if target == app.identifier or target == app.name:
                    app_identifier = app.identifier
                    app_name = app.name
                    break
            if mode == MODE.SPAWN.value:
                process_id = device.spawn([app_identifier])
                session = device.attach(process_id)
                device.resume(process_id)
                time.sleep(1)
            else:
                session = device.attach(app_name)
        else:
            session = device.attach(pid)
    else:
        if frida_server_ip != "":
            device = frida.get_device_manager().add_remote_device(frida_server_ip)
        else:
            device = frida.get_remote_device()
        if pid == None:
            processes = device.enumerate_processes()
            target = package
            for process in processes:
                if target == str(process.pid) or target == process.name:
                    process_name = process.name
                    process_id = process.pid
                    break
            if mode == MODE.SPAWN.value:
                process_id = device.spawn([binary_path])
                session = device.attach(process_id)
                device.resume(process_id)
                time.sleep(1)
            else:
                session = device.attach(process_id)
        else:
            session = device.attach(pid)

    def on_message(message, data):
        print(message)

    with open("javascript/core.js", "r") as f:
        jscode = f.read()

    script = session.create_script(jscode)
    script.on("message", on_message)
    script.load()
    frida_api = script.exports_sync
    frida_api.SetConfig(config)

    info = frida_api.GetInfo()
    if mode == MODE.ATTACH.value:
        process_id = info["pid"]

    if run_mode == "medit":
        medit.run_loop(process_id, config, frida_api, info)
    else:
        memory_view_mode(frida_api, memoryview_address)


if __name__ == "__main__":
    args = sys.argv

    target = config["general"]["target"]
    targetOS = config["general"]["targetOS"]
    binary_path = config["general"]["binary_path"]
    run_mode = "medit"
    memoryview_address = None
    if "--memoryview" in args:
        memoryview_address = int(args[args.index("--memoryview") + 1], 16)
        run_mode = "memoryview"

    if targetOS in [OS.ANDROID.value, OS.IOS.value]:
        if target == "":
            if args[1] == "-p" or args[1] == "--pid":
                pid = int(args[2])
                main(None, pid, run_mode, memoryview_address)
            else:
                main(args[1], None, run_mode, memoryview_address)
        else:
            if run_mode == "memoryview":
                pid = int(args[2])
                main(None, pid, run_mode, memoryview_address)
            else:
                main(target, None, run_mode, memoryview_address)
    else:
        if target == "":
            if binary_path == "":
                if args[1] == "-p" or args[1] == "--pid":
                    pid = int(args[2])
                    main(None, pid, run_mode, memoryview_address)
                else:
                    main(args[1], None, run_mode, memoryview_address)
            else:
                main("", None, run_mode, memoryview_address)
        else:
            if run_mode == "memoryview":
                pid = int(args[2])
                main(None, pid, run_mode, memoryview_address)
            else:
                main(target, None, run_mode, memoryview_address)
