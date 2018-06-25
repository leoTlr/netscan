#!/usr/bin/python

import threading
import socket
from traceback import format_exc # debug
from .protocol_structs import IP, ICMP, Ether # udpSenderThread.run(), listenerThread.run()
from ctypes import sizeof # udpSenderThread.run()


class listenerThread(threading.Thread):
    """ Waits for packets to arrive and decodes them
        to check for 'ICMP: Port Unreachable' """

    def __init__(self, silent=False):
        threading.Thread.__init__(self, name='listener')
        self.stop_event = threading.Event()
        self.is_listening = False
        self.is_privileged = False
        self.silent = silent
        self.hostup_counter = 0
        self.hostup_set = set() # stores already captured ip's
        self.header_lst = []
        self.own_ip = None # becomes dest addr of first port unreachable reply

    def stop(self):
        self.stop_event.set()

    def stopped(self):
        return self.stop_event.is_set()

    def _initSocket(self):
        try:
            # outputs complete ethernet frames, needs root
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            self.is_privileged = True
            return sock
        except PermissionError:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            print('[WARNING] no permissions for raw socket -> no MAC-adresses')
            return sock
        except:
            print(format_exc())
            if not self.silent:
                print('[ERROR] could not create socket for listener. listener stopped')
            self.stop()

    def run(self):
        # use 'with'-cotext to ensure closing the socket
        with self._initSocket() as listener:
            if self.is_privileged:
                self._runPrivileged(listener)
            else:
                self._runNonPrivileged(listener)

    def _runPrivileged(self, listener):

        if not self.silent and not self.stopped():
            print('Listening for incoming packets...')

        while not self.stopped():

            # read a packet
            raw_packet = listener.recvfrom(65565)[0]
            eth_len = 14 # 18 byte if VLAN-Tag set, but need only 14 to determine

            # TODO: some MAC adresses seem to be wrong (not all)
            #       -> only own mac seems to be incorrect (it is 0)
            #       -> sould not be in output anyway (done)

            eth_header = Ether(raw_packet[:eth_len])

            if eth_header.has_vlan_tag:
                # need to increase offset to start of IP-header then
                eth_len = 18

            # 8 = IP
            if eth_header.type_id == 8:
                ip_header = IP(raw_packet[eth_len:eth_len+20])

                if ip_header.protocol == 'ICMP':
                    # ihl specifies offsed in 32-bit words -> ihl*4(bytes)=offset
                    offset = ip_header.ihl*4
                    buffer = raw_packet[eth_len+offset:eth_len+offset+sizeof(ICMP)]

                    icmp_header = ICMP(buffer)

                    # check for destination port unreachable message
                    if icmp_header.code == 3 and icmp_header.type == 3:

                        # prevent double counting
                        # note that this is not absolutely failsafe
                        # first reply can be the package sent to own IP
                        # TODO find better solution without sending additional packages
                        if not self.own_ip:
                            self.own_ip = ip_header.dst
                        if self.own_ip == ip_header.src:
                            continue

                        if not ip_header.src in self.hostup_set:
                            if not self.silent:
                                ip_str = '{}'.format(ip_header.src_addr)
                                mac_str = '{}'.format(eth_header.src_addr)
                                print('[*] Host up:    {:<16}  {}'.format(ip_str, mac_str))

                            self.hostup_set.add(ip_header.src)
                            self.hostup_counter += 1

            self.is_listening = True

    def _runNonPrivileged(self, listener):
        if not self.silent and not self.stopped():
            print('Listening for incoming packets (unprivileged)...')

        listener.setblocking(False)
        h_set = set()

        while not self.stopped():
            try:
                raw_header = listener.recvfrom(512)[0]
                ip_header = IP(raw_header)
                h_set.add(ip_header)
            except socket.error:
                pass
            except:
                print(format_exc())
            self.is_listening = True

        self.printHeaderFields(h_set)


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

    def __init__(self, network_addr, broadcast_addr, closed_port=65333, silent=False):
        threading.Thread.__init__(self, name='udp-sender')
        self.closed_port = closed_port
        self.network_addr = network_addr
        self.broadcast_addr = broadcast_addr
        self.start_event = threading.Event()
        self.stop_event = threading.Event()
        self.silent = silent

    def stop(self):
        self.stop_event.set()

    def stopped(self):
        return self.stop_event.is_set()

    def _initSocket(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            return sock
        except:
            if not self.silent:
                print('[ERROR] could not create socket for sender. sender stopped')
            self.stop()
            exit(-1)

    def run(self):
        with self._initSocket() as sender:
            # gettring released outside
            self.start_event.wait()

            if not self.silent and not self.stopped():
                addr_str = self.bin2DottedDecimal(self.network_addr)
                subnet = 32-(self.broadcast_addr-self.network_addr).bit_length()
                print('Sending packets to {}/{}'.format(addr_str, subnet))

            for bin_addr in self.addressGenerator(self.network_addr, self.broadcast_addr):
                if self.stopped():
                    # in case of stop msg from outsde: stop sending
                    break;
                dd_addr = self.bin2DottedDecimal(bin_addr)
                try:
                    sender.sendto(bytes(8), (dd_addr, self.closed_port))
                except:
                    if not self.silent:
                        print('[WARNING] sendig of packet to {} failed.'.format(dd_addr))

    def addressGenerator(self, network_addr, broadcast_addr):
        # yields every host-address in subnet
        # if /32, yield this address
        if network_addr == broadcast_addr:
            yield network_addr # for /32 check this addr
        elif network_addr+1 == broadcast_addr:
            if not self.silent:
                print('[Warning] no host-addresses in /31 network')
            raise StopIteration # dont yield
        else:
            addr = network_addr
            addr += 1 # increment first to get the first host-address
            while addr < broadcast_addr: # dont yield broadcast-address
                yield addr
                addr += 1

    def bin2DottedDecimal(self, bin_addr):
        return '.'.join(map(str, bin_addr.to_bytes(4, 'big')))
