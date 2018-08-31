#!/usr/bin/python

import threading
import socket
import os, pwd, grp # listenerThread.dropPrivileges()
from traceback import format_exc # debug
from .protocol_structs import IP, ICMP, Ether # udpSenderThread.run(), listenerThread.run()
from ctypes import sizeof # udpSenderThread.run()


class unprivThread(threading.Thread):
    """ add dropPrivileged() mehtod to thread """

    # TODO make class abstract somehow to prevent instanciation 

    def __init__(self):
        self.quiet = True

    def dropPrivileges(self):
        """ drop root-privileges if run with sudo  """

        if os.getuid() != 0:
            # not root anyway
            return

        # get name of sudo user (returns None if ran in root shell)
        user_name = os.getenv('SUDO_USER')

        # there is no $SUDO_USER run in root shell
        if not user_name:
            if not self.quiet: # TODO 
                print('[WARNING] can not drop privileges to $SUDO_USER if running in root shell')
            return
        
        # get uid/gid from name (only works if running with sudo, not with su root)
        pwnam = pwd.getpwnam(user_name) # struct with user uid and gid

        # remove group privileges
        os.setgroups([])

        # set new uid/gid
        os.setgid(pwnam.pw_gid)
        os.setuid(pwnam.pw_uid)

        # set umask
        os.umask(0o22)


class listenerThread(unprivThread):
    """ Waits for packets to arrive and decodes them
        to check for 'ICMP: Port Unreachable' """

    def __init__(self, quiet=False):
        threading.Thread.__init__(self, name='listener')
        self.stop_event = threading.Event()
        self.is_listening = False
        self.is_privileged = False
        self.prepare_xml_data = False
        self.quiet = quiet
        self.hostup_counter = 0
        self.hostup_set = set() # stores already captured ip's
        self.header_lst = []
        self.xml_set = set() # store human-readable ip and mac for saving in xml
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
        except PermissionError: # TODO: ICMP echo schould pe possible like this without root privileges
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
            if not self.quiet:
                print('[WARNING] no permissions for raw socket -> no MAC-adresses')
            return sock
        except:
            print(format_exc())
            if not self.quiet:
                print('[ERROR] could not create socket for listener. listener stopped')
            self.stop()
        finally:
            # privileges only needed for socket creation
            self.dropPrivileges()

    def run(self):
        # use 'with'-cotext to ensure closing the socket
        with self._initSocket() as listener:
            if self.is_privileged:
                self._runPrivileged(listener)
            else:
                # TODO
                self._runNonPrivileged(listener)

    def _runPrivileged(self, listener):

        if not self.quiet and not self.stopped():
            print('Listening for incoming packets...')

        while not self.stopped():

            # read a packet
            raw_packet = listener.recv(65565)
            eth_len = 14 # 18 byte if VLAN-Tag set, but need only 14 to determine

            # some MAC adresses seem to be wrong (not all)
            #       -> only own mac seems to be incorrect (it is 0) but why?
            #       -> sould not be in output anyway (done)

            eth_header = Ether(raw_packet[:eth_len])

            if eth_header.has_vlan_tag:
                # need to increase offset to start of IP-header then
                eth_len = 18

            # 8 = IP
            if eth_header.type_id == 8:
                ip_header = IP(raw_packet[eth_len:eth_len+20])

                if ip_header.protocol == 'ICMP':
                    # ihl specifies offset in 32-bit words -> ihl*4(bytes)=offset
                    offset = ip_header.ihl*4
                    buffer = raw_packet[eth_len+offset:eth_len+offset+sizeof(ICMP)]

                    icmp_header = ICMP(buffer)

                    # check for destination port unreachable message
                    if icmp_header.code == 3 and icmp_header.type == 3:

                        # prevent double counting
                        # note that this is not absolutely failsafe
                        # first reply can be the package sent to own IP
                        # TODO find better solution without sending additional packages
                        #       -> socket.getaddrinfo(None, 65333) returns only localhost, not actual addr
                        #       -> socket.gethostbyname(socket.gethostname()) returns addr, but probably sends additional packets
                        if not self.own_ip:
                            self.own_ip = ip_header.dst
                        if self.own_ip == ip_header.src:
                            continue

                        if not ip_header.src in self.hostup_set:
                            ip_str = '{}'.format(ip_header.src_addr)
                            mac_str = '{}'.format(eth_header.src_addr)
                            if not self.quiet:
                                print('[*] Host up:    {:<16}  {}'.format(ip_str, mac_str))
                            if self.prepare_xml_data:
                                self.xml_set.add((ip_str, mac_str))

                            self.hostup_set.add(ip_header.src)
                            self.hostup_counter += 1

            self.is_listening = True

    def _runNonPrivileged(self, listener): # TODO

        if not self.quiet and not self.stopped():
            print('Listening for incoming packets (unprivileged)...')

        listener.setblocking(False)
        h_set = set()

        while not self.stopped():
            try:
                raw_header = listener.recv(512)
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


class udpSenderThread(unprivThread):
    """ Thread for sending UDP packets to every Host in subnet.
        Default Port is 65333. This port hopefully is closed on target systems,
        so they return 'ICMP: Port unreachable' """

    def __init__(self, network_addr, broadcast_addr, closed_port=65333, quiet=False):
        threading.Thread.__init__(self, name='udp-sender')
        self.closed_port = closed_port
        self.network_addr = network_addr
        self.broadcast_addr = broadcast_addr
        self.start_event = threading.Event()
        self.stop_event = threading.Event()
        self.quiet = quiet

    def stop(self):
        self.stop_event.set()

    def stopped(self):
        return self.stop_event.is_set()

    def _initSocket(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            return sock
        except:
            if not self.quiet:
                print('[ERROR] could not create socket for sender. sender stopped')
            self.stop()
            exit(-1)

    def run(self):

        # privileges not needed for sender socket
        self.dropPrivileges()

        with self._initSocket() as sender:
            
            # gettring released outside
            self.start_event.wait()

            if not self.quiet and not self.stopped():
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
                    if not self.quiet:
                        print('[WARNING] sendig of packet to {} failed.'.format(dd_addr))

    def addressGenerator(self, network_addr, broadcast_addr):
        """ yields every host-address in subnet
            if /32, yield this address """
            
        if network_addr == broadcast_addr:
            yield network_addr # for /32 check this addr
        elif network_addr+1 == broadcast_addr:
            if not self.quiet:
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
