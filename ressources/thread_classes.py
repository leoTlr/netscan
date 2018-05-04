#!/usr/bin/python

import threading
import socket
from traceback import format_exc # debug
from .protocol_structs import IP, ICMP, Ether # udpSenderThread.run(), listenerThread.run()
from ctypes import sizeof # udpSenderThread.run()


class listenerThread(threading.Thread):
    """ Waits for packets to arrive and decodes them
        to check for 'ICMP: Port Unreachable' """

    def __init__(self):
        threading.Thread.__init__(self, name='listener')
        self._stop_event = threading.Event()
        self.is_listening = False
        self.hostup_counter = 0
        self.hostup_set = set() # stores checksums of headers to prevent counting them multiple times
        self.header_lst = []


    def stop(self):
        self._stop_event.set()

    def stopped(self):
        return self._stop_event.is_set()

    def run(self):
        try:
            addr = socket.gethostname()

            # family=AF_PPACKET and proto=socket.ntohs(0x0003)
            # outputs complete ethernet frames
            sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

            print('Listening for incoming packets...')
            while not self.stopped():

                # read a packet
                raw_packet = sniffer.recvfrom(65565)[0]
                eth_len = 14 # without VLAN-tag 14, with 18. Only 14 needed to determine

                eth_header = Ether(raw_packet[:eth_len])
                if eth_header.has_vlan_tag:
                    print('VLAN FRAME: ', unpack('!6s6s4s4sH', raw_packet[:18]))
                    eth_len = 18

                #tst_eth = unpack('!6s6sH', raw_packet[:14])
                #field_id = socket.ntohs(tst_eth[2])
                #print('type_id: ', field_id, eth_header.type_id, eth_header.protocol)

                # 8 = IP
                if eth_header.type_id == 8:
                    ip_header = IP(raw_packet[eth_len:eth_len+20])

                    if ip_header.protocol == 'ICMP':
                        offset = ip_header.ihl*4
                        buffer = raw_packet[eth_len+offset:eth_len+offset+sizeof(ICMP)]

                        icmp_header = ICMP(buffer)

                        # check for destination port unreachable message
                        if icmp_header.code == 3 and icmp_header.type == 3:
                            if not icmp_header.checksum in self.hostup_set:
                                print('[*] Host up:    IPv4: {}    MAC: {}'.format(
                                    ip_header.src_addr, eth_header.src_addr))
                                self.hostup_set.add(icmp_header.checksum)
                                self.hostup_counter += 1

                self.is_listening = True

        except:
            print(format_exc())
        finally:
            self.printHeaderFields(self.header_lst)
            try:
                sniffer.close()
            except:
                pass

    def printHeaderFields(self, headers): # for debug
        cntr = 1
        try:
            for header in headers:
                print('Header nr {}:'.format(cntr))
                cntr += 1
                for tup in header._fields_:
                    if tup[0] == 'src':
                        print('-{:15}{}'.format('src:', header.src_addr))
                    elif tup[0] == 'dst':
                        print('-{:15}{}'.format('dst:', header.dst_addr))
                    else:
                        print('-{:15}{}'.format(tup[0]+':', getattr(header, tup[0])))
                try:
                    if header.has_vlan_tag:
                        print('Has VLAN tag')
                except:
                    pass
                print()
        except:
            pass


class udpSenderThread(threading.Thread):
    """ Thread for sending UDP packets to every Host in subnetself.
        Default Port is 65333. This port hopefully is closed on target systems,
        so they return 'ICMP: Port unreachable' """

    def __init__(self, netw_part, hostparts_tuple_list, closed_port=65333):
        threading.Thread.__init__(self, name='udp-sender')
        self.closed_port = closed_port
        self.netw_part = netw_part
        self.hostparts_tuple_list = hostparts_tuple_list
        self.network_address = self.calc_netw_address(self.netw_part)
        self.waitlock = threading.Lock()
        self.start_event = threading.Event()
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def stopped(self):
        return self._stop_event.is_set()

    def run(self):
        try:
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            #self.waitlock.acquire() # gettring released outside
            self.start_event.wait()

            print('Sending packets to {}'.format(self.network_address))
            for bin_addr in self.yield_next_addr_bin(self.netw_part, self.hostparts_tuple_list):
                if self.stopped():
                    break; # in case of stop msg from outsde: stop sending
                dd_addr = self.bin_to_dotted_decimal(bin_addr)
                try:
                    sender.sendto(bytes(8), (dd_addr, self.closed_port))
                    #print('++ pkg sent to {}, {}'.format(dd_addr, 66533))
                except:
                    #print('sendig failed')
                    pass
        except KeyboardInterrupt:
            print('sender thread interrupted by user')
        except:
            print(format_exc())
        finally:
            try:
                sender.close()
            except:
                pass
        #print('Sender thread finished')

    def yield_next_addr_bin(self, netw_part, hostparts_tuple_list):
        # subnet adress generator function
        for item in hostparts_tuple_list:
            yield netw_part+''.join([str(digit) for digit in item])
        if len(netw_part)==32:
            yield netw_part

    def bin_to_dotted_decimal(self, bin_addr):
        blocklst = [int(bin_addr[i:i+8], base=2) for i in range(0,32,8)]
        return '{}.{}.{}.{}'.format(*blocklst)
        # time elapsed:  11.701575517654419 for this with /12 subnet
        # time elapsed:  21.34294080734253 for '.'join([str(item) for item in blocklist])
        # maybe test bitstring module

    def calc_netw_address(self, netw_part):
        # returns the network address of given subnet in cidr notation
        subnet = len(netw_part)
        dd_netw_address = self.bin_to_dotted_decimal(netw_part+'0'*(32-len(netw_part)))
        return '{}/{}'.format(dd_netw_address, subnet)
