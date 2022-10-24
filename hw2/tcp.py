import socket
from struct import *

__all__ = ["tcp",]

class tcp:
    def __init__(self):
        self.source = 0
        self.dest = 0
        self.seq = 0
        self.ack_seq = 0
        self.doff = 0
        self.fin = 0
        self.syn = 0
        self.rst = 0
        self.psh = 0
        self.ack = 0
        self.urg = 0
        self.windows_size = socket.htons(1)  # maximum allowed window size
        self.check = 0
        self.urg_ptr = 0
        self.data = 0

    def decode_packet(self, packet):
        self.source = format(ord(packet[0])*256+ord(packet[1]))
        self.dest = format(ord(packet[2])*256+ord(packet[3]))
        self.seq =  format(((ord(packet[4]) * 256 + ord(packet[5])) * 256 + ord(packet[6])) * 256 + ord(packet[7]))
        self.ack_seq =  format(((ord(packet[8]) * 256 + ord(packet[9])) * 256 + ord(packet[10])) * 256 + ord(packet[11]))
        data_offset = format(ord(packet[12]), 'b')
        data_offset = '0'*(8-len(data_offset)) + data_offset
        self.doff = int(data_offset[0:4], 2)
        flags = format(ord(packet[13]), 'b')
        flags = '0' * (8 - len(flags)) + flags
        self.ack = int(flags[3], 2)
        self.syn = int(flags[6], 2)
        self.fin = int(flags[7], 2)
        self.windows_size = format(ord(packet[14])*256+ord(packet[15]))
        self.data = packet[4*self.doff:]
        self.check = format(ord(packet[2])*256+ord(packet[3]))

    def make_header(self):
        offset_res = (self.doff << 4) + 0
        flags = self.fin + (self.syn << 1) + (self.rst << 2) + (self.psh << 3) + (self.ack << 4) + (self.urg << 5)
        header = pack('!HHLLBBH', self.source, self.dest, self.seq, self.ack_seq, offset_res, flags, self.windows_size) + pack('H', self.check) + pack('H', self.urg_ptr)
        self.doff = len(header) / 4
        offset_res = (self.doff << 4) + 0
        header = pack('!HHLLBBH', self.source, self.dest, self.seq, self.ack_seq, offset_res, flags, self.windows_size) + pack('H', self.check) + pack('H', self.urg_ptr)
        return header

    @staticmethod
    def checksum(msg):
        s = 0
        for i in range(0, len(msg), 2):
            try:
                w = ord(msg[i]) + (ord(msg[i + 1]) << 8)
            except:
                w =  ord(msg[i])
            s = s + w
        s = (s >> 16) + (s & 0xffff)
        s = s + (s >> 16)
        s = ~s & 0xffff
        return s

    def make_packet_with_data(self, data):
        header = self.make_header()
        packet = header + data
        self.check = self.checksum(packet)
        header = self.make_header()
        return header + data

    def make_packet_no_data(self):
        header = self.make_header()
        self.check = self.checksum(header)
        header = self.make_header()
        return header


