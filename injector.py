# coding=utf-8

'''injector 是一个注射器，实现的功能是：把数据包从链路层传递到指定网卡上'''

import socket


class Injector(object):
    def __init__(self, network_interface):
        self._if = network_interface
        self.raws = socket.socket(socket.PF_PACKET,
                                  socket.SOCK_RAW,
                                  socket.htons(0x800))
        self.raws.bind((network_interface, socket.htons(0x0800)))

    def inject(self, packet):
        if isinstance(packet, str):
            if len(packet) >= 15:
                self.raws.send(packet)

            else:
                pass

