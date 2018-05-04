## netscan <br>

+ host-discovery tool
 + sends UDP-packets to a (hopefully) closed port to every machine in given network
 and then waits for ICMP Port unreachable responses
+ use either CIDR-type IPv4 (i.e.: 192.168.2.0/24) or dotted decimal + netmask
