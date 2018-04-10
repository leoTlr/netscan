#!/usr/bin/python

import threading
import socket
from traceback import format_exc
from .protocol_structs import IP, ICMP
from ctypes import sizeof


class listenerThread(threading.Thread):
    """ Waits for packets to arrive and decodes them
        to check for 'ICMP: Port Unreachable' """

    def __init__(self):
        threading.Thread.__init__(self, name='listener')
        self.shutdown = False
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
                self.is_listening = True
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
    def __init__(self, netw_part, hostparts_tuple_list):
        threading.Thread.__init__(self, name='udp-sender')
        self.netw_part = netw_part
        self.hostparts_tuple_list = hostparts_tuple_list
        self.waitlock = threading.Lock()

    def run(self):
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.waitlock.acquire() # gettring released outside

        print('Sending packets to subnet')
        tb = None
        for bin_addr in self.yield_next_addr_bin(self.netw_part, self.hostparts_tuple_list):
            dd_addr = self.bin_to_dotted_decimal(bin_addr)
            try:
                sender.sendto(bytes(8), (dd_addr, 65333)) # 65333 = hopefully unsused port
                #print('++ pkg sent to {}, {}'.format(dd_addr, 66533))
            except:
                #print('sendig failed')
                tb = format_exc()
                print(tb)
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
