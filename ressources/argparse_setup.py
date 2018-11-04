import argparse

desc = """
Host discovery tool.
Will list and count all responding devices in given network by sending an
UDP-packet to a closed port at each address in network and waiting for
ICMP: Port unreachable responses.
"""

def setup_argparse():

    parser = argparse.ArgumentParser(description=desc)
    save_compare_group = parser.add_mutually_exclusive_group()
    save_save_file_group = save_compare_group.add_mutually_exclusive_group()

    parser.add_argument('ip_address', metavar='IPv4-address', help='IPv4 Address in CIDR-notation')
    parser.add_argument('-nm', '--netmask', help='netmask in dotted decimal notation \
                        (only needed if ip_address not in CIDR-notation)', metavar='NM')
    parser.add_argument('-w', '--wait', help='define time (seconds) to wait for responses \
                        after all packets are sent. Default 2', type=int, metavar='SEC')
    parser.add_argument('-p', '--port', help='define a closed UDP port to use. Default 65333',
                        type=int)
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='only output number of discovered hosts (or number of changes since\
                        save if -c is selected)')
    parser.add_argument('--sort', action='store_true', help='sort output by IP before printing')
    save_save_file_group.add_argument('-s', '--save', action='store_true', help='save discovered hosts \
                            as .xml file in ./saved_scans')
    save_save_file_group.add_argument('-sf', '--save-file', metavar='PATH', help='like -s but save to provided \
                            directory or file')
    save_compare_group.add_argument('-c', '--compare', metavar='PATH', help='scan and compare with \
                        saved hosts in file. If this is selected with -q, the number of\
                        changes is returned')
                        
    return parser.parse_args()