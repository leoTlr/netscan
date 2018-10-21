from re import fullmatch # regex address validation (is_valid_dd_netmask())
from datetime import datetime # prepare_path()
import xml.etree.ElementTree as ET # save_xml(), compare_xml()
from xml.dom import minidom # save_xml()
from pathlib import Path, WindowsPath, PosixPath # save_xml()
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

def prepare_path(path):
    # test if path is file or directory (create if needed)
    # ensure it is writable
    # return (path, timestamp) to writable file else (None, timestamp)

    assert isinstance(path, str)

    p = Path(path)
    timestamp = '{:%Y-%m-%d-%H-%M-%S}'.format(datetime.now())
    filename = 'scan_{}.xml'.format(timestamp)

    if not p.exists():
        if path.endswith('/') or path.endswith('\\'):
            try:
                p.mkdir(mode=0o777, parents=True)
            except:
                logging.error('Directory for save could not be created')
                return (None, timestamp)
        else:
            p = _try_append_else_create(p)
            return (p, timestamp)
    
    if p.is_dir():
        p = _try_touch(p, filename)
        return (p, timestamp)
    if p.is_file():
        p = _try_append_else_create(p)
        return (p, timestamp)

    logging.error('failed to prepare save file')
    return (None, timestamp)

def _try_touch(path, filename):
    # try to create file at path
    # return filepath on success else None

    assert isinstance(path, Path) and path.is_dir()
    assert isinstance(filename, str)

    filepath = path / filename # concatenate to new path
    try:
        filepath.touch()
        return filepath
    except FileExistsError:
        logging.warning('File already exists. Will append scan')
        return filepath
    except:
        logging.error('Could not write to {}'.format(filepath))
        return None       

def _try_append_else_create(filepath):
    # try to append to file
    # return path on success alse None
    
    assert (isinstance(filepath, Path) or isinstance(filepath, PosixPath) \
            or isinstance(filepath, WindowsPath))

    try:
        if filepath.is_file():
            logging.info('File already exists. Will append scan')
        with filepath.open(mode='a', ) as f:
            f.close()
        return filepath
    except:
        logging.error('Could not write to {}'.format(filepath))
        return None

def save_xml(data_set, network_str, path='./saved_scans/'):
    # save discovered hosts as xml file
    # no path checking done, use prepare_path()

    assert isinstance(data_set, set)
    assert isinstance(network_str, str) and '/' in network_str

    save_file, timestamp = prepare_path(path)

    assert (isinstance(save_file, Path) or isinstance(save_file, PosixPath) \
                                        or isinstance(save_file, WindowsPath))
    assert isinstance(timestamp, str)

    attributes = {}
    attributes['network'] = network_str
    attributes['timestamp'] = timestamp

    scan = ET.Element('scan', attrib=attributes)

    for ip_str, mac_str in data_set:
        host = ET.SubElement(scan, 'host')
        ET.SubElement(host, 'ip').text = ip_str
        ET.SubElement(host, 'mac').text = mac_str

    # using ET.ElementTree(scan).write(fd) does no indentation
    pretty_xml_string = minidom.parseString(ET.tostring(scan)).toprettyxml(indent="  ")

    try:
        with save_file.open(mode='a') as xml_file:
            xml_file.write(pretty_xml_string)
    except PermissionError:
        logging.error('Saving scan failed (no permission)')
    except:
        logging.error('Saving scan failed')
    else:
        logging.info('Saved scan to "{}"'.format(save_file))

def compare_xml(data_set, network, path):
    # compare discovered hosts with a .xml save of previous search
    # TODO: - path checking
    #       - file syntax checking

    saved_set = set()
    changes_less = 0
    changes_more = 0

    with open(path, 'r') as xml_file:
        tree = ET.parse(xml_file)
        scan = tree.getroot()

        logging.info('Comparison with saved scan:')
        if network != scan.get('network'):
            logging.warning('comparing scans from different networks')

        for host in scan:
            for ip, mac in ((a,b) for a in host.iter('ip') for b in host.iter('mac')):
                h_tup = (ip.text, mac.text)
                if h_tup not in data_set:
                    logging.info('[-] {:<16}  {}'.format(h_tup[0], h_tup[1]))
                    changes_less += 1
                saved_set.add(h_tup)

        for ip, mac in data_set:
            if (ip, mac) not in saved_set:
                logging.info('[+] {:<16}  {}'.format(ip, mac))
                changes_more += 1

        changes_combined = changes_less+changes_more
        logging.info('no longer online: {}'.format(changes_less))
        logging.info('additional hosts: {}'.format(changes_more))
        logging.info('combined changes: {}'.format(changes_combined))

        return changes_combined

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