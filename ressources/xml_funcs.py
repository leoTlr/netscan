from datetime import datetime # _prepare_path()
import xml.etree.ElementTree as ET # save_xml(), compare_xml()
from xml.dom import minidom # save_xml()
from pathlib import Path, WindowsPath, PosixPath # save_xml()
import logging


def save_xml(data_dict, network_str, path='./saved_scans/'):
    # save discovered hosts as xml file
    # uses _prepare_path() for path checking

    assert isinstance(data_dict, dict)
    assert isinstance(network_str, str) and '/' in network_str

    save_file, timestamp = _prepare_path(path)

    assert (isinstance(save_file, Path) or isinstance(save_file, PosixPath) \
                                        or isinstance(save_file, WindowsPath))
    assert isinstance(timestamp, str)

    attributes = {}
    attributes['network'] = network_str
    attributes['timestamp'] = timestamp

    # example tree:
    # <scan network="1.2.3.0/24" timestamp="2018-10-24-18-03-15">
    #   <host IP="1.2.3.4" MAC="aa:bb:cc:dd:ee:ff"/>
    #   ...
    # </scan>
    scan_tree = ET.Element('scan', attrib=attributes)
    for ip_str, mac_str in data_dict.values():
        host = ET.SubElement(scan_tree, 'host')
        host.set('IP', ip_str)
        host.set('MAC', mac_str)
        
    # using ET.ElementTree(scan).write(file) does no indentation or new lines
    pretty_xml_string = minidom.parseString(ET.tostring(scan_tree)).toprettyxml(indent="  ")

    try:
        with save_file.open(mode='a') as xml_file:
            xml_file.write(pretty_xml_string)
    except PermissionError:
        logging.error('Saving scan failed (no permission)')
    except:
        logging.error('Saving scan failed')
    else:
        logging.info('Saved scan to "{}"'.format(save_file))

def compare_xml(data_dict, network, path):
    # compare discovered hosts with a .xml save of previous search
    # return #changes from saved scan
    # more info if loglevel <= info
    assert isinstance(data_dict, dict)
    assert isinstance(network, str) and '/' in network
    assert isinstance(path, str)

    xml_file_hosts = set()
    changes_less = 0
    changes_more = 0

    scan = _try_parse_xml_file(path)
    if not isinstance(scan, ET.Element):
        # only continue if opening and parsing file succeeded
        # already enough debug info logged at this point
        return
    
    logging.info('Comparison with saved scan:')
    if network != scan.get('network'):
        logging.warning('Comparing scans from different networks')
    for host in scan:
        host_keys = host.keys()
        if host.tag != 'host':
            logging.warning('Invalid element found. Skipping element "{}"'.format(host.tag))
            continue
        elif 'IP' not in host_keys:
            logging.warning('Host-Element has no attribute "ip". Skipping element')
            continue
        elif 'MAC' not in host_keys:
            logging.warning('Host-Element has no attribute "mac". Skipping element')
            continue
        
        ip = host.get('IP')
        mac = host.get('MAC')
        host_tuple = (ip, mac)
        xml_file_hosts.add(host_tuple)

        if host_tuple not in data_dict.values():
            logging.info('[-] {:<16}  {}'.format(host_tuple[0], host_tuple[1]))
            changes_less += 1
            
    for ip, mac in data_dict.values():
        if (ip, mac) not in xml_file_hosts:
            logging.info('[+] {:<16}  {}'.format(ip, mac))
            changes_more += 1

    changes_combined = changes_less + changes_more
    logging.info('No longer online: {}'.format(changes_less))
    logging.info('Additional hosts: {}'.format(changes_more))
    logging.info('Combined changes: {}'.format(changes_combined))

    return changes_combined

def _prepare_path(path):
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
            logging.warning('File already exists. Will append scan')
        with filepath.open(mode='a', ) as f:
            f.close()
        return filepath
    except:
        logging.error('Could not write to {}'.format(filepath))
        return None

def _try_parse_xml_file(path):
    # return file obj on success
    # file obj is automatically destroyed after use because opened in with-context

    assert isinstance(path, str)

    try:
        with open(path, 'r') as xml_file:

            # interpret file
            try:
                tree = ET.parse(xml_file)
                scan = tree.getroot()
            except:
                logging.error('Could not parse given XML-file. Does it contain more than one XML-tree?')
                logging.debug('debug info:\n', exc_info=True)
                return
            else:
                if scan.tag != 'scan' or not 'network' in scan.attrib:
                    logging.error('Could not interpret XML-file')
                    return
                return scan

    except PermissionError:
        logging.error('No permission to open XML-file')
        return
    except FileNotFoundError:
        logging.error('File not found')
        return
    except Exception:
        logging.error('Opening file failed')
        logging.debug('', exc_info=True)
        return