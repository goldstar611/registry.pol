#!/usr/bin/python3

import enum
import struct
from typing import List


class RegFile:
    # https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/registry-policy-file-format
    REGFILE_SIGNATURE = b'\x50\x52\x65\x67'  # Defined as 0x67655250
    REGISTRY_FILE_VERSION = 0x00000001  # Initially defined as 1, then incremented each time the file format is changed.

    def __init__(self):
        self.entries: List[Entry] = []

    @classmethod
    def load(cls, filename: str):
        with open(filename, "rb") as f:
            magic = struct.unpack("<4s", f.read(4))[0]
            if magic != cls.REGFILE_SIGNATURE:
                raise ValueError("Missing Registry.pol magic string: {0}".format(magic))

            version = struct.unpack("<I", f.read(4))[0]
            if version != cls.REGISTRY_FILE_VERSION:
                raise ValueError("Incorrect Registry.pol version: {0}".format(version))

            decoded = f.read().decode("UTF-16-LE")

        entries = [Entry.loads(body) for body in decoded.split("]") if body]
        c = cls()
        c.entries = entries
        return c


class Entry:
    def __init__(self, key: str, value: str, regtype: int, size: int, data: bytes):
        self.key = key
        self.value = value
        self.regtype = regtype
        self.size = size
        self.data = data

    @classmethod
    def loads(cls, body: str):
        # The body consists of registry values in the following format.
        # [key;value;type;size;data]
        key, value, reg_type, size, d = body.split(";")

        # Fix ups

        # Key (remove leading '[' and trailing '\x00'
        key = key[1:].rstrip("\x00")
        # Value (remove trailing '\x00')
        value = value.rstrip("\x00")
        # Type
        reg_type = struct.unpack("<H", reg_type.encode())[0]
        # Size
        size = struct.unpack("<H", size.encode())[0]
        # Data (remove trailing '\x00' only for REG_SZ types)
        if RegType(reg_type) == RegType.REG_SZ:
            d = d.rstrip("\x00")

        return cls(key=key, value=value, regtype=reg_type, size=size, data=d.encode())


# https://learn.microsoft.com/en-us/windows/win32/shell/hkey-type
class RegType(enum.Enum):
    REG_NONE = 0
    REG_SZ = 1
    REG_EXPAND_SZ = 2
    REG_BINARY = 3
    REG_DWORD = 4
    REG_DWORD_BIG_ENDIAN = 5
    REG_LINK = 6
    REG_MULTI_SZ = 7
    REG_RESOURCE_LIST = 8
    REG_FULL_RESOURCE_DESCRIPTOR = 9
    REG_RESOURCE_REQUIREMENTS_LIST = 10
    REG_QWORD = 11


def main(filename):
    """Print contents of Registry.pol file"""
    reg_file = RegFile.load(filename)
    pprint_entries(reg_file.entries)


def pprint_entries(entries):
    for entry in entries:
        print(entry.key)
        print("    value: {0}".format(entry.value))
        print("    type:  {0} {1}".format(entry.regtype, RegType(entry.regtype).name))
        print("    size:  {0}".format(entry.size))
        print("    data:  {0}".format(entry.data))
        print()


if __name__ == "__main__":
    import sys
    main(sys.argv[1])
