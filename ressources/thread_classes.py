#!/usr/bin/python

import threading
import socket
from traceback import format_exc # debug
from .protocol_structs import IP, ICMP # udpSenderThread.run()
from ctypes import sizeof # udpSenderThread.run()


class listenerThread(threading.Thread):
    """ Waits for packets to arrive and decodes them
        to check for 'ICMP: Port Unreachable' """

    def __init__(self):
        threading.Thread.__init__(self, name='listener')
        #self.shutdown = False
        self._stop_event = threading.Event()
        self.is_listening = False
        self.hostup_counter = 0

    def stop(self):
        self._stop_event.set()

    def stopped(self):
        return self._stop_event.is_set()

    def run(self):
        try:
            addr = socket.gethostname()
            sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sniffer.bind((addr, 0))
            sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            tb = None # assignment for traceback

            print('Listening for incoming packets...')
            while not self.stopped():

                # read a packet
                raw_buffer = sniffer.recvfrom(65565)[0]

                # create IP header from first 20 bytes
                ip_header = IP(raw_buffer[:20])
                #sniffed_headers.append(ip_header)

                #print detected protocol and hosts
                #print('[*] Protocol: {} {} -> {}'.format(
                #    ip_header.protocol, ip_header.src_addr, ip_header.dst_addr))

                if ip_header.protocol == 'ICMP':
                    offset = ip_header.ihl*4
                    buf = raw_buffer[offset:offset+sizeof(ICMP)]
                    icmp_header = ICMP(buf)
                    #print('ICMP -> Type: {}, Code: {}'.format(
                    #    icmp_header.type, icmp_header.code))

                    # check for destination port unreachable message
                    if icmp_header.code == 3 and icmp_header.type == 3:
                        print('[*] Host up: {}'.format(ip_header.src_addr))
                        self.hostup_counter += 1

                self.is_listening = True

        except:
            tb = format_exc()
        finally:
            if tb:
                print(tb)
            try:
                sniffer.close()
            except:
                print(format_exc())
            #print('Listener stopped')



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
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def stopped(self):
        return self._stop_event.is_set()

    def run(self):
        try:
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            self.waitlock.acquire() # gettring released outside

            print('Sending packets to {}'.format(self.network_address))
            tb = None
            for bin_addr in self.yield_next_addr_bin(self.netw_part, self.hostparts_tuple_list):
                if self.stopped():
                    break; # in case of stop msg from outsde: stop sending
                dd_addr = self.bin_to_dotted_decimal(bin_addr)
                try:
                    sender.sendto(bytes(8), (dd_addr, self.closed_port))
                    #print('++ pkg sent to {}, {}'.format(dd_addr, 66533))
                except:
                    #print('sendig failed')
                    #tb = format_exc()
                    #print(tb)
                    pass
        except KeyboardInterrupt:
            print('sender thread interrupted by user')
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
