import socket

ETH_P_ALL = 0x0003
MAX_PACKET_SIZE = 65535

class Sniffer:
    def __init__(self, interface, packet_size=MAX_PACKET_SIZE):
      self.interface = interface
      self.packet_size = packet_size
      self._sniffer = socket.socket(family=socket.AF_PACKET, type=socket.SOCK_RAW,
                                    proto=socket.htons(ETH_P_ALL))

    def start(self):
        self._sniffer.bind((self.interface, ETH_P_ALL))

    def sniff(self):
        while True:
           data = self._sniffer.recv(self.packet_size)
           yield data

    def stop(self):
        self._sniffer.close()
