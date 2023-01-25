from struct import pack, unpack


class StructPack:
    def __init__(self, value, _type):
        self.value = value
        self.type = _type

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
            bytecode = bytes.fromhex(self.value.replace(" ",""))
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
            size = len(self.value.replace(" ",""))/2
        return size


class StructUnpack:
    def __init__(self, bytecode, _type):
        self.bytecode = bytecode
        self.type = _type

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
        return value
