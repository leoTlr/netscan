import threading
import socket
import os, pwd, grp # listenerThread.dropPrivileges()
from .protocol_structs import IP, ICMP, Ether # udpSenderThread.run(), listenerThread.run()
from ctypes import sizeof # listenerThread.run()
import logging

class baseThread(threading.Thread):
    """ bundles common methods and a shared Event """

    listener_ready = threading.Event() # needs to be shared by all threads

    # TODO make class abstract somehow to prevent instanciation 

    def __init__(self, quiet=True, name='baseThread'):
        super().__init__(name=name)
        self.stop_event = threading.Event()
        self.name = name
        self.quiet = quiet
        self.error = False

    def dropPrivileges(self):
        """ drop root-privileges if run with sudo  """

        if os.getuid() != 0:
            return # not root anyway

        # get name of sudo user (returns None if ran in root shell)
        user_name = os.getenv('SUDO_USER')

        # there is no $SUDO_USER run in root shell
        if not user_name:
            logging.warning('can not drop privileges to $SUDO_USER if running in root shell')
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

    def stop(self, abnormal=False):
        if abnormal:
            self.error = True
        self.stop_event.set()

    def stopped(self):
        return self.stop_event.is_set()
    
    def stoppedAbnormally(self):
        return self.error


class listenerThread(baseThread):
    """ Waits for packets to arrive and decodes them
        to check for 'ICMP: Port Unreachable' """

    def __init__(self, quiet=False):
        super().__init__(name='listener', quiet=quiet)
        self.prepare_xml_data = False
        self.hostup_counter = 0
        self.hostup_set = set() # stores already captured ip's
        self.xml_set = set() # store human-readable ip and mac for saving in xml
        self.own_ip = None # becomes dest addr of first port unreachable reply

    def _initSocket(self):
        try:
            # outputs complete ethernet frames, needs root
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            self.is_privileged = True
            return sock
        except PermissionError:
            logging.error('no permissions for raw socket. listener stopped')
            self.stop(True)
            exit(-1)
        except Exception as e:
            logging.error('could not create socket for listener. listener stopped')
            logging.debug(e)
            self.stop(True)
            exit(-1)
        finally:
            # privileges only needed for socket creation
            self.dropPrivileges()

    def run(self):

        # use 'with'-cotext to ensure closing the socket
        with self._initSocket() as listener:

            if not self.stopped():
                logging.info('Listening for incoming packets...')

            self.listener_ready.set()

            while not self.stopped():

                # read a packet
                raw_packet = listener.recv(65565) # TODO set on max combined header length

                # need 14 bytes to determine if vlan tag present
                eth_header = Ether(raw_packet[:14])
                eth_len = eth_header.length # actual length

                # 8 = IP
                if eth_header.ethernet_type_id == 8:
                    ip_header = IP(raw_packet[eth_len:eth_len+20])

                    if ip_header.protocol == 'ICMP':
                        # ihl specifies offset in 32-bit words -> ihl*4(bytes)=offset
                        offset = ip_header.ihl*4
                        buffer = raw_packet[eth_len+offset:eth_len+offset+sizeof(ICMP)]

                        icmp_header = ICMP(buffer)

                        # check for destination port unreachable message
                        if icmp_header.code == 3 and icmp_header.type == 3:

                            # prevent counting package sent to own ip
                            # TODO find better solution without sending additional packages
                            #       -> socket.getaddrinfo(None, 65333) returns only localhost, not actual addr
                            #       -> socket.gethostbyname(socket.gethostname()) returns addr, but probably sends additional packets
                            if not self.own_ip:
                                self.own_ip = ip_header.dst_addr
                            if self.own_ip == ip_header.src_addr:
                                continue     

                            # prevent double counting
                            if not ip_header.src_addr in self.hostup_set:
                                ip_str = ip_header.src_addr
                                mac_str = eth_header.src_addr
                
                                logging.info('[*] Host up:    {:<16}  {}'.format(ip_str, mac_str))
                                if self.prepare_xml_data:
                                    self.xml_set.add((ip_str, mac_str))

                                self.hostup_set.add(ip_header.src_addr)
                                self.hostup_counter += 1


class udpSenderThread(baseThread):
    """ Thread for sending UDP packets to every Host in subnet.
        Default Port is 65333. This port hopefully is closed on target systems,
        so they return 'ICMP: Port unreachable' """

    def __init__(self, network_addr, broadcast_addr, closed_port=65333, quiet=False):
        super().__init__(name='udp-sender', quiet=quiet)
        self.closed_port = closed_port
        self.network_addr = network_addr
        self.broadcast_addr = broadcast_addr

    def _initSocket(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            return sock
        except:
            logging.error('could not create socket for sender. sender stopped')
            self.stop(True)
            exit(-1)
        finally:
            self.dropPrivileges()

    def run(self):

        # privileges not needed for sender socket
        self.dropPrivileges()

        with self._initSocket() as sender:
            
            # gettring released in listener thread
            self.listener_ready.wait()

            if not self.stopped():
                addr_str = self.bin2DottedDecimal(self.network_addr)
                subnet = 32-(self.broadcast_addr-self.network_addr).bit_length()
                logging.info('Sending packets to {}/{}'.format(addr_str, subnet))

            for bin_addr in self.addressGenerator(self.network_addr, self.broadcast_addr):
                if self.stopped():
                    # in case of stop msg from outsde: stop sending
                    break;
                dd_addr = self.bin2DottedDecimal(bin_addr)
                try:
                    sender.sendto(bytes(8), (dd_addr, self.closed_port))
                except:
                    logging.warning('sendig of packet to {} failed.'.format(dd_addr))

    def addressGenerator(self, network_addr, broadcast_addr):
        """ yields every host-address in subnet
            if /32, yield this address """
            
        if network_addr == broadcast_addr:
            yield network_addr # for /32 check this addr
        elif network_addr+1 == broadcast_addr:
            if not self.quiet:
                logging.warning('no host-addresses in /31 network')
            raise StopIteration # dont yield
        else:
            addr = network_addr
            addr += 1 # increment first to get the first host-address
            while addr < broadcast_addr: # dont yield broadcast-address
                yield addr
                addr += 1

    def bin2DottedDecimal(self, bin_addr):
        return '.'.join(map(str, bin_addr.to_bytes(4, 'big')))
