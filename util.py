from struct import pack, unpack
from keystone import *
from capstone import *


def assemble_to_bytes(assembly_code, architecture, mode):
    ks_engine = Ks(architecture, mode)
    encoding, count = ks_engine.asm(assembly_code)
    bytecode = bytes.fromhex("".join(format(x, "02x") for x in encoding))
    return bytecode


def bytes_to_assemble(bytecode, architecture, mode, offset=0):
    cs_engine = Cs(architecture, mode)
    if offset == 0:
        asmcode = "\n".join(
            [f"{i.mnemonic} {i.op_str}" for i in cs_engine.disasm(bytecode, offset)]
        )
    else:
        asmcode = "\n".join(
            [
                f"{hex(i.address)}:{i.mnemonic} {i.op_str}"
                for i in cs_engine.disasm(bytecode, offset)
            ]
        )
    return asmcode


class StructPack:
    def __init__(self, value, _type, _arch):
        self.value = value
        self.type = _type
        if _arch == "ia32":
            self.arch = KS_ARCH_X86
            self.mode = KS_MODE_32
        elif _arch == "x64":
            self.arch = KS_ARCH_X86
            self.mode = KS_MODE_64
        elif _arch == "arm":
            self.arch = KS_ARCH_ARM
            self.mode = KS_MODE_ARM
        elif _arch == "arm64":
            self.arch = KS_ARCH_ARM64
            self.mode = KS_MODE_LITTLE_ENDIAN

    def pack(self):
        if self.type == "word":
            bytecode = pack("<H", int(self.value))
        elif self.type == "dword":
            bytecode = pack("<I", int(self.value))
        elif self.type == "qword":
            bytecode = pack("<Q", int(self.value))
        elif self.type == "float":
            bytecode = pack("<f", float(self.value))
        elif self.type == "double":
            bytecode = pack("<d", float(self.value))
        elif self.type == "utf8":
            bytecode = self.value.encode()
        elif self.type == "aob":
            bytecode = bytes.fromhex(self.value.replace(" ", ""))
        elif self.type == "asm":
            bytecode = assemble_to_bytes(self.value, self.arch, self.mode)
        return bytecode

    def size(self):
        if self.type == "word":
            size = 2
        elif self.type == "dword":
            size = 4
        elif self.type == "qword":
            size = 8
        elif self.type == "float":
            size = 4
        elif self.type == "double":
            size = 8
        elif self.type == "utf8":
            size = len(self.value)
        elif self.type == "aob":
            size = len(self.value.replace(" ", "")) / 2
        elif self.type == "asm":
            size = int(len(assemble_to_bytes(self.value, self.arch, self.mode)) / 2)
        return size


class StructUnpack:
    def __init__(self, bytecode, _type, _arch, offset=0):
        self.bytecode = bytecode
        self.type = _type
        if _arch == "ia32":
            self.arch = CS_ARCH_X86
            self.mode = CS_MODE_32
        elif _arch == "x64":
            self.arch = CS_ARCH_X86
            self.mode = CS_MODE_64
        elif _arch == "arm":
            self.arch = CS_ARCH_ARM
            self.mode = CS_MODE_ARM
        elif _arch == "arm64":
            self.arch = CS_ARCH_ARM64
            self.mode = CS_MODE_LITTLE_ENDIAN
        self.offset = offset

    def unpack(self):
        if self.type == "word":
            value = unpack("<H", self.bytecode)[0]
        elif self.type == "dword":
            value = unpack("<I", self.bytecode)[0]
        elif self.type == "qword":
            value = unpack("<Q", self.bytecode)[0]
        elif self.type == "float":
            value = unpack("<f", self.bytecode)[0]
        elif self.type == "double":
            value = unpack("<d", self.bytecode)[0]
        elif self.type == "utf8":
            value = self.bytecode.decode("utf-8")
        elif self.type == "aob":
            value = self.bytecode.hex()
        elif self.type == "asm":
            value = bytes_to_assemble(self.bytecode, self.arch, self.mode, self.offset)

        return value
