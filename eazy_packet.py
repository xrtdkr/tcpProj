# coding=utf-8

from scapy.all import send


class EasyPacket(object):
    def __init__(self, packet, protocol, dst_mac, src_mac, dst_ip, src_ip, dport=None, sport=None):
        self.packet = packet
        self.protocol = protocol

        self.dst_mac = dst_mac
        self.src_mac = src_mac

        self.dst_ip = dst_ip
        self.src_ip = src_ip

        self.dport = dport
        self.sport = sport

    def _send_packet(self):
        send(self.packet)



