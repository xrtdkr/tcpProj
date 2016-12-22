# tcpProj



# coding=utf-8

'''catcher是从目的网卡上抓取数据的一个程序，为了避免回环，我们要做一些相应的匹配规则'''

from scapy.all import sniff
from scapy.all import send, conf
from scapy.all import sendp
from scapy.all import *
conf.sniff_promisc = True

def catcher(network_interface):
    pass


def send_packet(packet, interface):
    sendp(packet, iface=interface)



def packet_sniff(network_interface):
    def prn(packets):
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
        print "===================== log here ==================="
        print "packet captured~"
        packets.show()
        print " mac the packet: " + str(src_mac) + "======>" + str(dst_mac)
        print " mac the packet: " + str(src_ip) + "======>" + str(dst_ip)
        print "=====================log end ====================="

        ''' 下面做一些匹配上的规则 '''
        
        send_packet(packets, inject_interface)

    sniff(iface=network_interface, prn=prn)


capture_interface = "enp1s0"
inject_interface = "enx3c46d8d41b50"

while(1):
    packet_sniff(capture_interface)


