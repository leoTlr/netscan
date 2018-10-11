#!/usr/bin/python

import struct
import socket
from ctypes import *

""" Structures with c-type fields as container for packet data  """

class Ether(Structure):
    _fields_ = [
        ('dst', c_uint16*3),
        ('src', c_uint16*3),
        ('type_id', c_ushort), # not 802.1Q VLAN TPID, just regular ether type field
    ]

    def __new__(self, socket_buffer):
        self.dst_addr = socket_buffer[:6] # grab the bytes objects directly
        self.src_addr = socket_buffer[6:12] # before they get put into int

        # concatenate bytes to type_id
        id = 0b0
        id += (socket_buffer[12]<<8)
        id += socket_buffer[13]

        # check for vlan tag
        if id == 0x8100:
            self.length = 18 # bytes
        else:
            self.length = 14

        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        # make the dst and src addresses human-readable
        self.dst_addr = self._convert_addresses(self.dst_addr)
        self.src_addr = self._convert_addresses(self.src_addr)

        self.protocol_map = {8:'IP'} # TODO

        try:
            self.protocol = self.protocol_map[self.type_id]
        except:
            self.protocol = str(self.type_id)

    def _convert_addresses(self, address_bytelst):
        return '{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}'.format(*address_bytelst)

class IP(Structure):
    _fields_ = [
        ('ihl', c_ubyte, 4),
        ('version', c_ubyte, 4),
        ('tos', c_ubyte),
        ('len', c_ushort),
        ('id', c_ushort),
        ('offset', c_ushort),
        ('ttl', c_ubyte),
        ('protocol_num', c_ubyte),
        ('sum', c_ushort),
        ('src', c_uint32),
        ('dst', c_uint32)
    ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        self.protocol_map = {1:'ICMP', 6:'TCP', 17:'UDP'}

        # pack addr to bytes-obj and convert this to dotted decimal
        self.src_addr = socket.inet_ntoa(struct.pack('<L', self.src))
        self.dst_addr = socket.inet_ntoa(struct.pack('<L', self.dst))

        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

class ICMP(Structure):
    _fields_ = [
        ('type', c_ubyte),
        ('code', c_ubyte),
        ('checksum', c_ushort),
        ('unused', c_ushort),
        ('next_hop_mtu', c_ushort)
    ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        pass
