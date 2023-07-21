from __future__ import annotations

from pathlib import Path
import threading
from importlib_metadata import version
from rich import box
from rich.console import RenderableType
from rich.json import JSON
from rich.markdown import Markdown
from rich.pretty import Pretty
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.reactive import reactive
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Static,
    Switch,
    TextLog,
    Label,
    Checkbox,
    RadioButton,
    RadioSet,
    Tabs,
)
import util
import scanner
import api
import platform
import re
import os
import subprocess
import traceback
import lldbauto
from capstone import *
from capstone.arm64 import *
from collections import Counter

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

WELCOME_MD = """

## Tsubame

**Cross Platform TUI based process memory analyzer.**
"""

MESSAGE = ""


class Body(ScrollableContainer):
    pass


class Title(Static):
    pass


class DarkSwitch(Horizontal):
    def compose(self) -> ComposeResult:
        yield Switch(value=self.app.dark)
        yield Static("Dark mode toggle", classes="label")

    def on_mount(self) -> None:
        self.watch(self.app, "dark", self.on_dark_change, init=False)

    def on_dark_change(self) -> None:
        self.query_one(Switch).value = self.app.dark

    def on_switch_changed(self, event: Switch.Changed) -> None:
        self.app.dark = event.value


class Welcome(Container):
    def compose(self) -> ComposeResult:
        yield Static(Markdown(WELCOME_MD))
        yield Button("Start", variant="success")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.app.add_note("[b magenta]Start!")
        self.app.query_one(".location-first").scroll_visible(duration=0.5, top=True)


class OptionGroup(Container):
    pass


class SectionTitle(Static):
    pass


class Message(Static):
    pass


class Version(Static):
    def render(self) -> RenderableType:
        return f"[b]v{version('textual')}"


class Sidebar(Container):
    def compose(self) -> ComposeResult:
        yield Title("Tsubame")
        yield OptionGroup(Message(MESSAGE), Version())
        yield DarkSwitch()


class AboveFold(Container):
    pass


class Section(Container):
    pass


class Column(Container):
    pass


class TextContent(Static):
    pass


class QuickAccess(Container):
    pass


class LocationLink(Static):
    def __init__(self, label: str, reveal: str) -> None:
        super().__init__(label)
        self.reveal = reveal

    def on_click(self) -> None:
        self.app.query_one(self.reveal).scroll_visible(top=True, duration=0.5)
        self.app.add_note(f"Scrolling to [b]{self.reveal}[/b]")


class SearchForm(Container):
    def compose(self) -> ComposeResult:
        yield Static("Scan Value", classes="label")
        yield Input(placeholder="Input Scan Value", id="scan_value_input")
        yield Static()
        with Horizontal(classes="scansetting_horizontal"):
            yield Button("Find", variant="primary", name="find", classes="scan_button")
            yield Button(
                "Filter", variant="primary", name="filter", classes="scan_button"
            )
            yield Button(
                "NearBy", variant="primary", name="nearby", classes="scan_button"
            )
            yield Input(
                placeholder="nearby back",
                id="nearby_back_value_input",
                classes="nearby_input",
            )
            yield Input(
                placeholder="nearby front",
                id="nearby_front_value_input",
                classes="nearby_input",
            )
        with Horizontal(classes="scanresult_horizontal"):
            yield Static("0", id="scan_progress")
            yield Static("", id="scan_founds")
        yield Static("Scan Type", classes="label")
        with Horizontal(classes="scantype_horizontal"):
            with Vertical():
                yield RadioButton("  int8", value=False, id="r1", name="r1_int8")
                yield RadioButton(" int16", value=False, id="r2", name="r2_int16")
                yield RadioButton(" int32", value=True, id="r3", name="r3_int32")
                yield RadioButton(" int64", value=False, id="r4", name="r4_int64")
            with Vertical():
                yield RadioButton(" uint8", value=False, id="r5", name="r5_uint8")
                yield RadioButton("uint16", value=False, id="r6", name="r6_uint16")
                yield RadioButton("uint32", value=False, id="r7", name="r7_uint32")
                yield RadioButton("uint64", value=False, id="r8", name="r8_uint64")
            with Vertical():
                yield RadioButton(" float", value=False, id="r9", name="r9_float")
                yield RadioButton("double", value=False, id="r10", name="r10_double")
                yield RadioButton("  utf8", value=False, id="r11", name="r11_utf8")
                yield RadioButton(" utf16", value=False, id="r12", name="r12_utf16")
            with Vertical():
                yield RadioButton("   aob", value=False, id="r13", name="r13_aob")
                yield RadioButton(" regex", value=False, id="r14", name="r14_regex")

        yield Static("Scan Memory Protection", classes="label")
        with Horizontal(classes="memory_protection_horizontal"):
            yield Checkbox("Read", True, id="read_checkbox")
            yield Checkbox("Write", True, id="write_checkbox")
            yield Checkbox("Execute", False, id="execute_checkbox")
        yield Static("Scan Memory Range", classes="label")
        with Horizontal(classes="range_horizontal"):
            yield Input(placeholder="Start Address(hex)", id="start_input", value="0")
            yield Input(
                placeholder="End Address(hex)",
                id="end_input",
                value="0x7FFFFFFFFFFFFFFF",
            )
            yield Button(
                "Range Reset",
                variant="primary",
                name="range_reset",
                id="range_reset_button",
            )

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        try:
            if event.button.name == "find":
                if scanner.Scanner.scan_complete:
                    self.screen.query_one(TextLog).write("find start")
                    read = "r" if self.query_one("#read_checkbox").value else "-"
                    write = "w" if self.query_one("#write_checkbox").value else "-"
                    execute = "x" if self.query_one("#execute_checkbox").value else "-"
                    permission = read + write + execute
                    start_address = int(self.query_one("#start_input").value, 16)
                    end_address = int(self.query_one("#end_input").value, 16)
                    value = self.query_one("#scan_value_input").value
                    scan_type = ""
                    for i in range(14):
                        if self.query_one(f"#r{i+1}").value:
                            scan_type = self.query_one(f"#r{i+1}").name.split("_")[1]
                    ACTIVE_SCAN.protect = permission
                    ACTIVE_SCAN.start_address = start_address
                    ACTIVE_SCAN.end_address = end_address
                    await ACTIVE_SCAN.find(value, scan_type)
            elif event.button.name == "filter":
                if scanner.Scanner.scan_complete:
                    self.screen.query_one(TextLog).write("filter start")
                    value = self.query_one("#scan_value_input").value
                    await ACTIVE_SCAN.filter(value)
            elif event.button.name == "nearby":
                if scanner.Scanner.scan_complete:
                    self.screen.query_one(TextLog).write("nearby start")
                    value = self.query_one("#scan_value_input").value
                    near_back_str = self.query_one("#nearby_back_value_input").value
                    near_front_str = self.query_one("#nearby_front_value_input").value
                    ACTIVE_SCAN.near_back = int(near_back_str, 0)
                    ACTIVE_SCAN.near_front = int(near_front_str, 0)
                    await ACTIVE_SCAN.filter(value)
            elif event.button.name == "range_reset":
                self.query_one("#start_input").value = "0"
                self.query_one("#end_input").value = "0x7FFFFFFFFFFFFFFF"
        except Exception as e:
            self.app.show_note(traceback.format_exc())

    def on_radio_button_changed(self, event: RadioButton.Changed) -> None:
        index = int(event.radio_button.name.split("_")[0][1:])
        if self.query_one(f"#r{index}").value:
            for i in range(14):
                if (i + 1) != index:
                    self.query_one(f"#r{i+1}").value = False
        else:
            flag = False
            for i in range(14):
                if self.query_one(f"#r{i+1}").value:
                    flag = True
                    break
            if not flag:
                self.query_one(f"#r{index}").value = True


class AddressView(Container):
    def compose(self) -> ComposeResult:
        with Horizontal(classes="scantab_horizontal"):
            yield Button(
                "Add Scan Tab",
                variant="primary",
                name="add_tab",
                classes="add_tab_button",
            )
            yield Button(
                "Remove Scan Tab",
                variant="primary",
                name="remove_tab",
                classes="remove_tab_button",
            )
        yield Tabs(
            "Scan 1",
        )
        yield Static("Scan Result", classes="label")
        yield DataTable(id="address_table")
        yield Static("Patch", classes="label")
        with Horizontal(classes="patch_horizontal"):
            yield Input(placeholder="Input Index", id="index_input")
            yield Input(placeholder="Input Value", id="value_input")
            yield Button(
                "Patch", variant="primary", name="patch", classes="patch_button"
            )
        yield Static("Memory View", classes="label")
        with Horizontal(classes="view_horizontal"):
            yield Input(placeholder="Input Index or Address(hex)", id="watch_input")
            yield Button(
                "Watch", variant="primary", name="watch", classes="watch_button"
            )
        yield Static("Watch Point", classes="label")
        with Horizontal(classes="watchpoint_horizontal", id="watchpoint_horizontal"):
            yield Input(
                placeholder="Input Index or Address(hex)", id="watch_point_input"
            )
            yield Button(
                "Set WatchPoint",
                variant="primary",
                name="watch_point",
                classes="watch_point_button",
            )
        with Vertical(classes="watchsetting_vertical"):
            yield Static("WatchPoint Type", classes="label")
            with Horizontal():
                yield RadioButton("Read", False, id="r1", name="r1_r_radiobutton")
                yield RadioButton("Write", False, id="r2", name="r2_w_radiobutton")
                yield RadioButton("Access", True, id="r3", name="r3_a_radiobutton")
            yield Static("WatchPoint Size", classes="label")
            with Horizontal():
                yield RadioButton("1", False, id="s1", name="s1_1_radiobutton")
                yield RadioButton("2", False, id="s2", name="s2_2_radiobutton")
                yield RadioButton("4", True, id="s3", name="s3_4_radiobutton")
                yield RadioButton("8", False, id="s4", name="s4_8_radiobutton")

    def on_mount(self) -> None:
        self.set_interval(30 / 60, self.update_address_view).resume()
        self.total_tab_count = 1
        self.active_tab_name = "Scan 1"
        self.tab_info_dict = {}

    def update_address_view(self) -> None:
        if scanner.Scanner.scan_complete:
            datatable = self.query_one("#address_table")
            top_index = int(datatable.scroll_y)
            for i in range(30):
                if datatable.is_valid_row_index(top_index + i):
                    address = ACTIVE_SCAN.address_list[top_index + i]["address"]
                    size = ACTIVE_SCAN.address_list[top_index + i]["size"]
                    ret = MEMORY_API.readprocessmemory(address, size)
                    if ret:
                        bytecode = ret
                        scan_type = ACTIVE_SCAN.scan_type
                        sup = util.StructUnpack(bytecode, scan_type)
                        value = sup.unpack()
                        try:
                            datatable.update_cell_at((top_index + i, 2), value)
                            datatable.refresh_row(top_index + i)
                        except:
                            break

    def on_button_pressed(self, event: Button.Pressed) -> None:
        global ACTIVE_SCAN
        try:
            if event.button.name == "patch":
                _type = ACTIVE_SCAN.scan_type
                index = int(self.query_one("#index_input").value) - 1
                value = self.query_one("#value_input").value
                sp = util.StructPack(value, _type)
                bytecode = sp.pack()
                ret = MEMORY_API.writeprocessmemory(
                    ACTIVE_SCAN.address_list[index]["address"],
                    bytecode,
                )
                if ret != True:
                    self.screen.query_one(TextLog).write(f"patch error")
            elif event.button.name == "watch":
                tmp = self.query_one("#watch_input").value
                if tmp[0:2] == "0x":
                    address = int(tmp, 16)
                else:
                    index = int(tmp) - 1
                    address = ACTIVE_SCAN.address_list[index]["address"]

                def run():
                    hostos = platform.system()
                    if hostos == "Darwin":
                        from applescript import tell

                        cwd = os.getcwd()
                        pycmd = f"python3 main.py -p {PID} --memoryview {hex(address)}"
                        tell.app("Terminal", 'do script "' + f"cd {cwd};{pycmd}" + '"')
                    elif hostos == "Windows":
                        subprocess.call(
                            f"python main.py -p {PID} --memoryview {hex(address)}",
                            creationflags=subprocess.CREATE_NEW_CONSOLE,
                        )
                    else:
                        print("Not Support")

                t1 = threading.Thread(target=run, daemon=True)
                t1.start()
            elif event.button.name == "watch_point":
                global LLDB
                if DEBUGSERVER_IP != "":
                    if (
                        self.query_one("#watch_point_input").value.lower().find("0x")
                        == 0
                    ):
                        address = int(self.query_one("#watch_point_input").value, 0)
                    else:
                        index = int(self.query_one("#watch_point_input").value) - 1
                        address = ACTIVE_SCAN.address_list[index]["address"]
                    for i in range(3):
                        if self.query_one(f"#r{i+1}").value:
                            bptype = self.query_one(f"#r{i+1}").name.split("_")[1]
                            break
                    for i in range(4):
                        if self.query_one(f"#s{i+1}").value:
                            bpsize = int(self.query_one(f"#s{i+1}").name.split("_")[1])
                            break
                    target_ip = DEBUGSERVER_IP.split(":")[0]
                    target_port = int(DEBUGSERVER_IP.split(":")[1])
                    if LLDB == None:
                        LLDB = lldbauto.LLDBAutomation(target_ip, target_port, CONFIG)
                        result = LLDB.attach(PID)
                        if result.decode()[0] == "T":
                            t1 = threading.Thread(
                                target=LLDB.debugger_thread, daemon=True
                            )
                            t1.start()
                            t2 = threading.Thread(
                                target=LLDB.interrupt_func, daemon=True
                            )
                            t2.start()
                            LLDB.add_note = scanner.Scanner.add_note
                        else:
                            self.app.add_note("attach error")
                            return
                    wp = {
                        "address": address,
                        "bpsize": int(bpsize),
                        "type": bptype,
                        "switch": True,
                        "enabled": False,
                    }
                    if LLDB.set_wp_count == 4:
                        self.app.add_note("The maximum number of watchpoints is 4.")
                    else:
                        LLDB.wp_info_list[LLDB.set_wp_count] = wp
                        watchpoint = WatchPoint()
                        self.screen.query_one("#watchpoint_view").mount(watchpoint)
                        watchpoint.set_var(wp, LLDB.set_wp_count)
                        LLDB.set_wp_count += 1
            elif event.button.name == "add_tab":
                tabs = self.query_one(Tabs)
                self.total_tab_count += 1
                tabname = f"Scan {self.total_tab_count}"
                if CONFIG["ipconfig"]["memory_server_ip"] == "":
                    scan = scanner.Scanner(FRIDA_API, CONFIG)
                else:
                    scan = scanner.MSScanner(FRIDA_API, CONFIG, tabname)
                SCAN_DICT[tabname] = scan
                tabs.add_tab(tabname)
                self.tab_info_dict[tabname] = {
                    "scan_value": "",
                    "nearby_back": "",
                    "nearby_front": "",
                    "scan_type": "int32",
                    "range_start": "0",
                    "range_end": "0x7FFFFFFFFFFFFFFF",
                    "protect": "rw-",
                }
            elif event.button.name == "remove_tab":
                tabs = self.query_one(Tabs)
                active_tab = tabs.active_tab
                if active_tab is not None:
                    if tabs.tab_count > 1:
                        SCAN_DICT.pop(self.active_tab_name)
                        tabs.remove_tab(active_tab.id)
                        self.tab_info_dict.pop(self.active_tab_name)
        except Exception as e:
            self.app.show_note(traceback.format_exc())

    def on_radio_button_changed(self, event: RadioButton.Changed) -> None:
        t = event.radio_button.name[0]
        index = int(event.radio_button.name.split("_")[0][1:])
        if t == "r":
            if self.query_one(f"#r{index}").value:
                for i in range(3):
                    if (i + 1) != index:
                        self.query_one(f"#r{i+1}").value = False
            else:
                flag = False
                for i in range(3):
                    if self.query_one(f"#r{i+1}").value:
                        flag = True
                        break
                if not flag:
                    self.query_one(f"#r{index}").value = True
        elif t == "s":
            if self.query_one(f"#s{index}").value:
                for i in range(4):
                    if (i + 1) != index:
                        self.query_one(f"#s{i+1}").value = False
            else:
                flag = False
                for i in range(4):
                    if self.query_one(f"#s{i+1}").value:
                        flag = True
                        break
                if not flag:
                    self.query_one(f"#s{index}").value = True

    def on_data_table_row_selected(self, event: DataTable.CellSelected) -> None:
        index = event.data_table.cursor_row + 1
        self.query_one("#index_input").value = str(index)
        self.query_one("#watch_input").value = event.data_table.get_cell_at(
            (index - 1, 1)
        )
        self.query_one("#watch_point_input").value = event.data_table.get_cell_at(
            (index - 1, 1)
        )

    def on_tabs_tab_activated(self, event: Tabs.TabActivated) -> None:
        global ACTIVE_SCAN
        if event.tab is None:
            pass
        else:
            datatable = self.query_one("#address_table")
            datatable.clear()
            self.old_active_tab_name = self.active_tab_name
            self.active_tab_name = event.tab.label_text
            ACTIVE_SCAN = SCAN_DICT[self.active_tab_name]
            for i, address in enumerate(ACTIVE_SCAN.address_list):
                if i >= ACTIVE_SCAN.max_list_num:
                    break
                datatable.add_row(*[i + 1, hex(address["address"]), address["value"]])
            searchform = self.app.query_one(SearchForm)
            ### save old tab info
            # scan value
            _value = searchform.query_one(f"#scan_value_input").value
            # nearby back
            _nearby_back = searchform.query_one(f"#nearby_back_value_input").value
            # nearby front
            _nearby_front = searchform.query_one(f"#nearby_front_value_input").value
            # scan type
            for i in range(14):
                if searchform.query_one(f"#r{i+1}").value:
                    _scan_type = searchform.query_one(f"#r{i+1}").name.split("_")[1]
            # search memory range
            _range_start = searchform.query_one(f"#start_input").value
            _range_end = searchform.query_one(f"#end_input").value
            # protect
            if searchform.query_one(f"#read_checkbox").value == True:
                _r = "r"
            else:
                _r = "-"
            if searchform.query_one(f"#write_checkbox").value == True:
                _w = "w"
            else:
                _w = "-"
            if searchform.query_one(f"#execute_checkbox").value == True:
                _x = "x"
            else:
                _x = "-"
            _protect = _r + _w + _x

            self.tab_info_dict[self.old_active_tab_name] = {
                "scan_value": _value,
                "nearby_back": _nearby_back,
                "nearby_front": _nearby_front,
                "scan_type": _scan_type,
                "range_start": _range_start,
                "range_end": _range_end,
                "protect": _protect,
            }
            # update new tab info
            if self.active_tab_name in self.tab_info_dict:
                # scan value
                scan_value = self.tab_info_dict[self.active_tab_name]["scan_value"]
                searchform.query_one(f"#scan_value_input").value = scan_value
                # nearby back
                nearby_back = self.tab_info_dict[self.active_tab_name]["nearby_back"]
                searchform.query_one(f"#nearby_back_value_input").value = nearby_back
                # nearby front
                nearby_front = self.tab_info_dict[self.active_tab_name]["nearby_front"]
                searchform.query_one(f"#nearby_front_value_input").value = nearby_front
                # scan type
                scan_type = self.tab_info_dict[self.active_tab_name]["scan_type"]
                for i in range(14):
                    if searchform.query_one(f"#r{i+1}").name.find(scan_type) != -1:
                        searchform.query_one(f"#r{i+1}").value = True
                        break
                # search memory range
                range_start = self.tab_info_dict[self.active_tab_name]["range_start"]
                range_end = self.tab_info_dict[self.active_tab_name]["range_end"]
                searchform.query_one(f"#start_input").value = range_start
                searchform.query_one(f"#end_input").value = range_end
                # protect
                protect = self.tab_info_dict[self.active_tab_name]["protect"]
                if protect.find("r") != -1:
                    searchform.query_one(f"#read_checkbox").value = True
                else:
                    searchform.query_one(f"#read_checkbox").value = False
                if protect.find("w") != -1:
                    searchform.query_one(f"#write_checkbox").value = True
                else:
                    searchform.query_one(f"#write_checkbox").value = False
                if protect.find("x") != -1:
                    searchform.query_one(f"#execute_checkbox").value = True
                else:
                    searchform.query_one(f"#execute_checkbox").value = False


class ModuleList(Container):
    Modules = []

    def compose(self) -> ComposeResult:
        yield Button(
            "Update", variant="primary", name="update", classes="update_button"
        )
        yield Static("Modules", classes="label")
        yield DataTable(id="module_table")
        with Horizontal(classes="dump_input_horizontal", id="dump_input_horizontal"):
            yield Input(
                placeholder="Input Index",
                classes="dump_input",
                id="dump_input",
                name="dump_input",
            )
            yield Button("Dump", variant="primary", name="dump", classes="dump_button")
        with Horizontal(
            classes="filter_input_horizontal", id="filter_input_horizontal"
        ):
            yield Input(
                placeholder="Filter Library Name",
                classes="filter_input",
                id="filter_input",
                name="filter_input",
            )
        yield Static("", id="dump_result")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        try:
            module_table = self.screen.query_one("#module_table")
            if event.button.name == "update":
                module_table.clear()
                modules = MEMORY_API.enummodules()
                self.Modules = modules
                for i, module in enumerate(modules):
                    module_table.add_row(
                        *[
                            i + 1,
                            module["name"],
                            module["base"],
                            hex(module["size"]),
                            module["path"],
                        ]
                    )
            elif event.button.name == "dump":
                index = int(self.query_one("#dump_input").value) - 1
                if len(self.Modules) > index:
                    name = self.Modules[index]["name"]
                    base = int(self.Modules[index]["base"], 0)
                    size = self.Modules[index]["size"]
                    ret = MEMORY_API.readprocessmemory(base, size)
                    if ret != False:
                        bytecode = ret
                        if not os.path.exists("dump"):
                            os.mkdir("dump")
                        with open(os.path.join("dump", name), mode="wb") as f:
                            f.write(bytecode)
                        self.query_one("#dump_result").update(f"{name}:dump success!")
                    else:
                        self.query_one("#dump_result").update(f"{name}:dump error!")
                else:
                    self.query_one("#dump_result").update("invalid index")
        except Exception as e:
            self.app.show_note(traceback.format_exc())

    def on_input_changed(self, event: Input.Changed) -> None:
        try:
            if event.input.name == "filter_input":
                module_table = self.screen.query_one("#module_table")
                modulename = self.query_one("#filter_input").value
                module_table.clear()
                if self.Modules == None:
                    return
                modules = self.Modules
                for i, module in enumerate(modules):
                    if module["name"].lower().find(modulename.lower()) != -1:
                        module_table.add_row(
                            *[
                                i + 1,
                                module["name"],
                                module["base"],
                                hex(module["size"]),
                                module["path"],
                            ]
                        )
        except Exception as e:
            self.app.show_note(traceback.format_exc())

    def on_data_table_row_selected(self, event: DataTable.CellSelected) -> None:
        index = event.data_table.cursor_row
        module_index = event.data_table.get_cell_at((index, 0))
        self.query_one("#dump_input").value = str(module_index)


class MemoryRegions(Container):
    def compose(self) -> ComposeResult:
        yield Button(
            "Update", variant="primary", name="update", classes="update_button"
        )
        yield Static("Regions", classes="label")
        yield DataTable(id="regions_table")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        try:
            self.screen.query_one(TextLog).write(event.button.name)
            regions_table = self.screen.query_one("#regions_table")
            if event.button.name == "update":
                regions_table.clear()
                regions = MEMORY_API.enumranges()
                for i, region in enumerate(regions):
                    if "file" in region:
                        path = region["file"]["path"]
                    else:
                        path = ""
                    regions_table.add_row(
                        *[
                            i + 1,
                            region["base"],
                            hex(region["size"]),
                            region["protection"],
                            path,
                        ]
                    )
        except Exception as e:
            self.app.show_note(traceback.format_exc())


class WatchPointView(Container):
    def compose(self) -> ComposeResult:
        yield Static("WatchPointView", classes="label")


class WatchPoint(Container):
    def compose(self) -> ComposeResult:
        yield Static("WatchPoint", id="watchpoint_label", classes="label")
        yield DataTable(id="watchpoint_table")
        with Horizontal():
            yield Button(
                "Remove Watch",
                variant="primary",
                name="remove",
                classes="remove_button",
            )
            yield Button(
                "Stop Watch",
                variant="primary",
                name="toggle_watch",
                classes="toggle_button",
            )
            yield Button(
                "Disassemble", variant="primary", name="disasm", classes="disasm_button"
            )
            yield Button("Nop", variant="primary", name="nop", classes="nop_button")

    def on_mount(self) -> None:
        self.set_interval(2 / 60, self.update_time, pause=True).resume()
        self.watchpoint_table = self.query_one(DataTable)
        self.watchpoint_table.add_column("Index", width=10)
        self.watchpoint_table.add_column("Count", width=10)
        self.watchpoint_table.add_column("Address", width=25)
        self.watchpoint_table.add_column("Symbol", width=25)
        self.watchpoint_table.add_column("Opcode", width=30)
        self.watchpoint_table.zebra_stripes = True
        self.watchpoint_table.cursor_type = "row"
        address = self.wp["address"]
        bpsize = self.wp["bpsize"]
        _type = self.wp["type"]
        self.query_one("#watchpoint_label").update(
            f"WatchPoint Address:{hex(address)} Type:{_type} Size:{bpsize}"
        )

    def set_var(self, wp, wp_index) -> None:
        self.wp = wp
        self.wp_index = wp_index
        self.table_info = []

    def update_time(self) -> None:
        event_list = []
        while not LLDB.debug_event[self.wp_index].empty():
            event_list.append(LLDB.debug_event[self.wp_index].get())
        filterd_event_list = [
            event for event in event_list if event["address"] == self.wp["address"]
        ]
        pc_counts = Counter(event["register"][32] for event in filterd_event_list)
        for pc, sum_count in pc_counts.items():
            result = [
                (index, x) for (index, x) in enumerate(self.table_info) if x["pc"] == pc
            ]
            if result != []:
                index = result[0][0]
                x = result[0][1]
                count = x["count"]
                self.watchpoint_table.update_cell_at((index, 1), count + sum_count)
                self.table_info[index]["count"] += sum_count
            else:
                ret = MEMORY_API.readprocessmemory(pc, 64)
                if ret != False:
                    bytecode = ret
                    for insn in md.disasm(bytecode, 0x1000):
                        opcode = (
                            insn.mnemonic
                            + " "
                            + insn.op_str.replace("[", "(").replace("]", ")")
                        )
                        break
                else:
                    opcode = "unknown"
                symbol = MEMORY_API.getsymbol(pc)
                self.watchpoint_table.add_row(
                    *[len(self.table_info) + 1, sum_count, hex(pc), symbol, opcode]
                )
                self.table_info.append({"pc": pc, "count": sum_count})

    def on_button_pressed(self, event: Button.Pressed) -> None:
        try:
            self.screen.query_one(TextLog).write(event.button.name)
            if event.button.name == "remove":
                LLDB.set_wp_count -= 1
                info = LLDB.wp_info_list[self.wp_index]
                if info["switch"] == True and info["enabled"] == True:
                    info["switch"] = False
                self.remove()
            elif event.button.name == "toggle_watch":
                if event.button.label._text[0] == "Stop Watch":
                    info = LLDB.wp_info_list[self.wp_index]
                    if info["switch"] == True and info["enabled"] == True:
                        info["switch"] = False
                    event.button.label._text = ["Start Watch"]
                else:
                    info = LLDB.wp_info_list[self.wp_index]
                    if info["switch"] == False and info["enabled"] == False:
                        info["switch"] = True
                    event.button.label._text = ["Stop Watch"]
            elif event.button.name == "disasm":
                index = self.watchpoint_table.cursor_row
                address = int(self.watchpoint_table.get_cell_at((index, 2)), 0)
                self.screen.query_one(DisassembleView).disasm(address)
                self.screen.query_one(DisassembleView).scroll_visible(
                    top=True, duration=0.2
                )
            elif event.button.name == "nop":
                index = self.watchpoint_table.cursor_row
                address = int(self.watchpoint_table.get_cell_at((index, 2)), 0)
                mov_x0_x0 = b"\xe0\x03\x00\xaa"
                MEMORY_API.writeprocessmemory(address, mov_x0_x0)
        except Exception as e:
            self.app.show_note(traceback.format_exc())


class DisassembleView(Container):
    def compose(self) -> ComposeResult:
        yield Static("Disassemble", id="disassemble_label", classes="label")
        yield DataTable(id="disassemble_table")

    def on_mount(self) -> None:
        self.disassemble_table = self.query_one(DataTable)
        self.disassemble_table.add_column("Address", width=15)
        self.disassemble_table.add_column("Symbol", width=20)
        self.disassemble_table.add_column("Bytes", width=20)
        self.disassemble_table.add_column("Opcode", width=40)
        self.disassemble_table.zebra_stripes = True
        self.disassemble_table.cursor_type = "row"

    def disasm(self, address) -> None:
        self.disassemble_table.clear()
        ret = MEMORY_API.readprocessmemory(address, 1024)
        if ret != False:
            bytecode = ret
            address_list = []
            for i, insn in enumerate(md.disasm(bytecode, address)):
                if i == 0:
                    symbol = MEMORY_API.getsymbol(insn.address)
                else:
                    symbol = ""
                opcode = (
                    insn.mnemonic
                    + " "
                    + insn.op_str.replace("[", "(").replace("]", ")")
                )
                self.disassemble_table.add_row(
                    *[
                        hex(insn.address),
                        symbol,
                        " ".join("{:02x}".format(x) for x in insn.bytes),
                        opcode,
                    ]
                )


class Window(Container):
    pass


class SubTitle(Static):
    pass


class Notification(Static):
    def on_mount(self) -> None:
        self.set_timer(3, self.remove)

    def on_click(self) -> None:
        self.remove()


class TsubameApp(App[None]):
    CSS_PATH = "design.css"
    TITLE = "Tsubame"
    BINDINGS = [
        ("ctrl+b", "toggle_sidebar", "Sidebar"),
        ("ctrl+t", "app.toggle_dark", "Toggle Dark mode"),
        ("ctrl+s", "app.screenshot()", "Screenshot"),
        ("f1", "app.toggle_class('TextLog', '-hidden')", "Notes"),
        Binding("ctrl+c,ctrl+q", "app.quit", "Quit", show=True),
    ]

    show_sidebar = reactive(False)

    def add_note(self, renderable: RenderableType) -> None:
        self.query_one(TextLog).write(renderable)

    def show_note(self, renderable: RenderableType) -> None:
        self.query_one(TextLog).clear()
        self.query_one(TextLog).write(renderable)
        self.query_one(TextLog).remove_class("-hidden")

    def compose(self) -> ComposeResult:
        example_css = Path(self.css_path[0]).read_text()
        yield Container(
            Sidebar(classes="-hidden"),
            Header(show_clock=False),
            TextLog(classes="-hidden", wrap=False, highlight=True, markup=True),
            Body(
                QuickAccess(
                    LocationLink("TOP", ".location-top"),
                    LocationLink("Memory Editor", ".location-editor"),
                    LocationLink("Module List", ".location-module-list"),
                    LocationLink("Memory Regions", ".location-memory-regions"),
                    LocationLink("Watch Point", ".location-watchpoint"),
                    LocationLink("Disassemble View", ".location-disassemble"),
                ),
                AboveFold(Welcome(), classes="location-top"),
                Column(
                    Section(
                        SectionTitle("Memory Editor"),
                        SearchForm(),
                        AddressView(),
                    ),
                    classes="location-editor location-first",
                ),
                Column(
                    Section(
                        SectionTitle("Module List"),
                        ModuleList(),
                    ),
                    classes="location-module-list",
                ),
                Column(
                    Section(
                        SectionTitle("Memory Regions"),
                        MemoryRegions(),
                    ),
                    classes="location-memory-regions",
                ),
                Column(
                    Section(
                        SectionTitle("Watch Point"),
                        WatchPointView(id="watchpoint_view"),
                    ),
                    classes="location-watchpoint",
                ),
                Column(
                    Section(
                        SectionTitle("Disassemble View"),
                        DisassembleView(id="disassemble_view"),
                    ),
                    classes="location-disassemble",
                ),
            ),
        )
        yield Footer()

    def action_open_link(self, link: str) -> None:
        self.app.bell()
        import webbrowser

        webbrowser.open(link)

    def action_toggle_sidebar(self) -> None:
        sidebar = self.query_one(Sidebar)
        self.set_focus(None)
        if sidebar.has_class("-hidden"):
            sidebar.remove_class("-hidden")
        else:
            if sidebar.query("*:focus"):
                self.screen.set_focus(None)
            sidebar.add_class("-hidden")

    def on_mount(self) -> None:
        self.add_note("Tsubame is running")
        address_table = self.query_one("#address_table")
        address_table.add_column("Index", width=10)
        address_table.add_column("Address", width=20)
        address_table.add_column("Value", width=80)
        address_table.cursor_type = "row"
        address_table.zebra_stripes = True
        module_table = self.query_one("#module_table")
        module_table.add_column("Index", width=10)
        module_table.add_column("Name", width=60)
        module_table.add_column("Base", width=15)
        module_table.add_column("Size", width=15)
        module_table.add_column("Path", width=180)
        module_table.zebra_stripes = True
        module_table.cursor_type = "row"
        ranges_table = self.query_one("#regions_table")
        ranges_table.add_column("Index", width=10)
        ranges_table.add_column("Base", width=15)
        ranges_table.add_column("Size", width=15)
        ranges_table.add_column("Protection", width=10)
        ranges_table.add_column("File", width=180)
        ranges_table.zebra_stripes = True
        self.query_one("Welcome Button", Button).focus()
        scanner.Scanner.progress = self.query_one("#scan_progress")
        scanner.Scanner.add_note = self.add_note
        scanner.Scanner.datatable = address_table

    def action_screenshot(self, filename: str | None = None, path: str = "./") -> None:
        """Save an SVG "screenshot". This action will save an SVG file containing the current contents of the screen.

        Args:
            filename: Filename of screenshot, or None to auto-generate.
            path: Path to directory.
        """
        self.bell()
        path = self.save_screenshot(filename, path)
        message = Text.assemble("Screenshot saved to ", (f"'{path}'", "bold green"))
        self.add_note(message)
        self.screen.mount(Notification(message))


def multiply_number(s, n):
    num_str = re.search(r"%%(\d+)%%", s)
    if num_str is None:
        return False
    multiplied_num = int(int(num_str.group(1)) * n / 1.5)
    t = s.replace(num_str.group(0), str(multiplied_num))

    return t


PID = None
FRIDA_API = None
MEMORY_API = None
MEMORY_SERVER = None
SCAN_DICT = {}
ACTIVE_SCAN = None
LLDB = None
DEBUGSERVER_IP = None
CONFIG = None
INFO = None


def exec(pid, config, frida_api, info):
    global PID
    global FRIDA_API
    global MEMORY_API
    global MEMORY_SERVER
    global ACTIVE_SCAN
    global SCAN_DICT
    global INFO
    global DEBUGSERVER_IP
    global CONFIG

    if config["ipconfig"]["memory_server_ip"] == "":
        scan = scanner.Scanner(frida_api, config)
        memory_api = api.FRIDA(frida_api, config)
    else:
        scan = scanner.MSScanner(frida_api, config, "Scan 1")
        memory_api = api.MEMORY_SERVER(frida_api, config)
        MEMORY_SERVER = memory_api
    PID = pid
    FRIDA_API = frida_api
    MEMORY_API = memory_api
    SCAN_DICT["Scan 1"] = scan
    ACTIVE_SCAN = scan
    INFO = info
    CONFIG = config
    DEBUGSERVER_IP = config["ipconfig"]["debugserver_ip"]

    screen_ratio = config["general"]["screen_ratio"]
    # convert css file
    with open("design_orig.css", mode="r") as f:
        lines = f.readlines()
        with open("design.css", mode="w") as ff:
            for line in lines:
                t = multiply_number(line, screen_ratio)
                if t != False:
                    ff.write(t)
                else:
                    ff.write(line)

    app = TsubameApp()
    app.run()
