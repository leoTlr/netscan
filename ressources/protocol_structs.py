import struct
import socket # IP
from ctypes import c_uint8, c_uint16, c_uint32, BigEndianStructure

""" Structures with c-type fields as container for packet data  """

class Ether(BigEndianStructure):
    _fields_ = [
        ('dst', c_uint16*3),
        ('src', c_uint16*3),
        ('type_id', c_uint16), # not 802.1Q VLAN TPID, just regular ether type field
    ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        # make the dst and src addresses human-readable
        self.dst_addr = self._convert_addresses(socket_buffer[:6])
        self.src_addr = self._convert_addresses(socket_buffer[6:12])

        # check for vlan tag
        if self.type_id == 0x8100:
            self.length = 18 # bytes
        else:
            self.length = 14

    def _convert_addresses(self, address_bytelst):
        return '{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}'.format(*address_bytelst)


class IP(BigEndianStructure):
    _fields_ = [
        ('version_and_ihl', c_uint8),
        ('tos', c_uint8),
        ('total_len', c_uint16),
        ('id', c_uint16),
        ('flags_and_fragment_offset', c_uint16),
        ('ttl', c_uint8),
        ('protocol_num', c_uint8),
        ('checksum', c_uint16),
        ('src', c_uint32),
        ('dst', c_uint32)
    ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        # convert address to dotted decimal
        self.src_addr = socket.inet_ntoa(struct.pack('!L', self.src))
        self.dst_addr = socket.inet_ntoa(struct.pack('!L', self.dst))

    @property
    def ip_version(self):
        return (self.version_and_ihl & 0xF0) >> 4

    @property
    def ip_ihl(self):
        return self.version_and_ihl & 0x0F

    @property
    def ip_flags(self):
        return (self.flags_and_fragment_offset & 0xE000) >> 13

    @property
    def offset(self):
        return self.flags_and_fragment_offset & 0x1FFF


class ICMP(BigEndianStructure):
    _fields_ = [
        ('type', c_uint8),
        ('code', c_uint8),
        ('checksum', c_uint16),
        ('rest', c_uint32)
    ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)
    
    def __init__(self, socket_buffer):
        pass