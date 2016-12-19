# coding=utf-8

import socket
from scapy.all import *
from scapy.all import sniff
from eazy_packet import EasyPacket
from injector import Injector
from Configure import injector_interface, capture_interface

conf.promisc = True
conf.sniff_promisc = True


class Catcher(object):
    def __init__(self, network_interface):
        self._if = network_interface

    def packet_sniff(self):

        def prn(packets):
            raw = packets.__str__()

            src_mac = packets[0][0].src
            dst_mac = packets[0][0].dst

            if IP in packets:

                src_ip = packets[0][1].src
                dst_ip = packets[0][1].dst
                proto = packets[0][1].proto
            else:
                src_ip = None
                dst_ip = None
                proto = None

            if TCP in packets:
                sport = packets[TCP].sport
                dport = packets[TCP].dport

            elif UDP in packets:
                sport = packets[UDP].sport
                dport = packets[UDP].dport

            else:
                sport = None
                dport = None

            easy_packet = EasyPacket(packet=packets,
                                     protocol=proto,
                                     src_mac=src_mac,
                                     dst_mac=dst_mac,
                                     src_ip=src_ip,
                                     dst_ip=dst_ip,
                                     dport=dport,
                                     sport=sport, )

            injector = Injector(injector_interface)
            injector.inject(packets)

            print "===================== log here ==================="
            print "packet captured~"
            packets.show()
            print " mac the packet: " + str(easy_packet.src_mac) + "======>" + str(easy_packet.dst_mac)
            print " mac the packet: " + str(easy_packet.src_ip) + "======>" + str(easy_packet.dst_ip)
            print "=====================log end ====================="

        sniff(iface=self._if, prn=prn)
