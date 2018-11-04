from re import fullmatch # regex address validation (is_valid_dd_netmask())
from datetime import datetime # prepare_path()
import socket # check_privileges()
import logging

def check_privileges():
    # try creating a socket to ensure sufficient privileges
    
    try: # raw socket of AF_PACKET needed for listener-thread
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)) as s:
            s.close()
            return True
    except PermissionError:
        logging.error('root needed')
        return False
    except:
        return False

def is_valid_portnr(portnr):
    if 1 <= portnr <= 65535:
        return True
    else:
        return False

def calc_addr_range(address, dd_netmask=None):
    # calculate network address and broadcast Address
    # out of given ip address string
    # input either CIDR-type address or dotted decimal and separate netmask

    # separate decimal str blocks into 4 ints
    if not dd_netmask:
        # if CIDR-type, also get subnet (i.e '24' for '.../24')
        dd_addr, subnet_str = address.split('/')
        addr_blocks = [int(block) for block in dd_addr.split('.')]
    else:
        addr_blocks = [int(block) for block in address.split('.')]

    # concatenate decimal blocks to address
    bin_addr = 0b0
    addr_blocks = zip((24, 16, 8, 0), addr_blocks)
    for lshift_val, block in addr_blocks:
        bin_addr += (block << lshift_val)

    if not dd_netmask:
        subnet = int(subnet_str)

        # eqal to ('1'*subnet)+('0'*(32-subnet)) as int
        # i.e 0b11111111111111111111111100000000 for /24
        bin_netm = (2**(32-(32-subnet))-1) << (32-subnet)

    else:
        netm_blocks = [int(block) for block in dd_netmask.split('.')]

        # concatenate decimal blocks to address
        bin_netm = 0b0
        netm_blocks = zip((24, 16, 8, 0), netm_blocks)
        for lshift_val, block in netm_blocks:
            bin_netm += (block << lshift_val)

        # i.e for /24: subnet=24
        subnet = 32-((((2**32)-1)-bin_netm).bit_length())

    network_addr = bin_addr&bin_netm
    broadcast_addr = network_addr+(2**(32-subnet)-1)

    return (network_addr, broadcast_addr, subnet)

def is_valid_cidr(address):
    # check if given ip address is valid
    # (for tye: 192.168.2.0/24)
    try:
        split = address.split('/')
        if len(split)==2:
            hostpart = split[0]
            split_hostpart = hostpart.split('.')
            subnet = int(split[1])
            if not 0<subnet<=32:
                return False
            elif not len(split_hostpart)==4:
                return False
            elif not all([0<=int(nr)<=255 for nr in split_hostpart]):
                return False
            else:
                return True
        else:
            return False
    except:
        return False

def is_valid_dd_netmask(address, netmask):
    # check if given ipv4 address and netmask are valid
    # (for type 192.168.2.0 255.255.255.0)
    try:
        addr_split = address.split('.')
        netm_split = netmask.split('.')
        bin_netm = '{0:08b}{1:08b}{2:08b}{3:08b}'.format(*[int(block) for block in netm_split])
        if not len(addr_split)==4:
            return False
        elif not all([0<=int(nr)<=255 for nr in addr_split]):
            return False
        elif not all([0<=int(nr)<=255 for nr in netm_split]):
            return False
        elif not fullmatch('^(1{0,31}0{0,31})$', bin_netm):
            # attention: pattern only checks for bin_netm being ones followed by zeroes
            # BUT also matches len(bin_netm) != 32
            # -> need to explicitly check len
            return False
        elif not len(bin_netm)==32:
            return False
        else:
            return True
    except:
        return False

def print_sorted(data_dict):
    # sort data by ip and print
    # keys are built like (ip << 48)+mac so it will sort after ip
    sorted_keys = sorted(data_dict.keys())
    for key in sorted_keys:
        logging.info('[*] Host up:    {:<16}  {}'.format(data_dict[key][0], data_dict[key][1]))

