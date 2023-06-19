from struct import pack, unpack


class StructPack:
    def __init__(self, value, _type):
        self.value = value
        self.type = _type

    def pack(self):
        if self.type == "int8":
            bytecode = pack("<b", int(self.value, 0))
        elif self.type == "int16":
            bytecode = pack("<h", int(self.value, 0))
        elif self.type == "int32":
            bytecode = pack("<i", int(self.value, 0))
        elif self.type == "int64":
            bytecode = pack("<q", int(self.value, 0))
        elif self.type == "uint8":
            bytecode = pack("<B", int(self.value, 0))
        elif self.type == "uint16":
            bytecode = pack("<H", int(self.value, 0))
        elif self.type == "uint32":
            bytecode = pack("<I", int(self.value, 0))
        elif self.type == "uint64":
            bytecode = pack("<Q", int(self.value, 0))
        elif self.type == "float":
            bytecode = pack("<f", float(self.value))
        elif self.type == "double":
            bytecode = pack("<d", float(self.value))
        elif self.type == "utf8":
            bytecode = self.value.encode()
        elif self.type == "aob":
            bytecode = bytes.fromhex(self.value.replace(" ", ""))
        return bytecode

    def size(self):
        if self.type == "int8":
            size = 1
        elif self.type == "int16":
            size = 2
        elif self.type == "int32":
            size = 4
        elif self.type == "int64":
            size = 8
        if self.type == "uint8":
            size = 1
        elif self.type == "uint16":
            size = 2
        elif self.type == "uint32":
            size = 4
        elif self.type == "uint64":
            size = 8
        elif self.type == "float":
            size = 4
        elif self.type == "double":
            size = 8
        elif self.type == "utf8":
            size = len(self.value)
        elif self.type == "aob":
            size = len(self.value.replace(" ", "")) / 2
        return size


class StructUnpack:
    def __init__(self, bytecode, _type, offset=0):
        self.bytecode = bytecode
        self.type = _type
        self.offset = offset

    def unpack(self):
        if self.type == "int8":
            value = unpack("<b", self.bytecode)[0]
        elif self.type == "int16":
            value = unpack("<h", self.bytecode)[0]
        elif self.type == "int32":
            value = unpack("<i", self.bytecode)[0]
        elif self.type == "int64":
            value = unpack("<q", self.bytecode)[0]
        elif self.type == "uint8":
            value = unpack("<B", self.bytecode)[0]
        elif self.type == "uint16":
            value = unpack("<H", self.bytecode)[0]
        elif self.type == "uint32":
            value = unpack("<I", self.bytecode)[0]
        elif self.type == "uint64":
            value = unpack("<Q", self.bytecode)[0]
        elif self.type == "float":
            value = unpack("<f", self.bytecode)[0]
        elif self.type == "double":
            value = unpack("<d", self.bytecode)[0]
        elif self.type == "utf8":
            value = self.bytecode.decode("utf-8", "replace")
        elif self.type == "aob":
            value = self.bytecode.hex()
        elif self.type == "regex":
            value = self.bytecode.decode("utf-8", "replace")
        return value
