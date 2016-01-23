import json

from .protocols.ethernet import EthernetFrame
from .protocols.ipv4 import IPv4Packet
from .protocols.icmp import ICMPPacket
from .protocols.udp import UDPDatagram
from .protocols.tcp import TCPSegment

ETHER_TYPES = {
    "IPV4": "0x0800",
}

IPV4_PROTOCOLS = {
    "ICMP": 1,
    "TCP": 6,
    "UDP": 17,
}

class Packet:
    def __init__(self, data):
        self.data = data
        self.headers = {}
        self._parse()

    def _parse(self):
        ethernet = EthernetFrame(self.data)
        self.headers["ethernet"] = ethernet.header()
        if self.headers["ethernet"]["type"] == ETHER_TYPES["IPV4"]:
            ipv4 = IPv4Packet(ethernet.payload)
            self.headers["ipv4"] = ipv4.header()
            if self.headers["ipv4"]["protocol"] == IPV4_PROTOCOLS["ICMP"]:
                icmp = ICMPPacket(ipv4.payload)
                self.headers["icmp"] = icmp.header()
            elif self.headers["ipv4"]["protocol"] == IPV4_PROTOCOLS["TCP"]:
                tcp = TCPSegment(ipv4.payload)
                self.headers["tcp"] = tcp.header()
            elif self.headers["ipv4"]["protocol"] == IPV4_PROTOCOLS["UDP"]:
                udp = UDPDatagram(ipv4.payload)
                self.headers["udp"] = udp.header()

    def to_json(self):
        return json.dumps(self.headers, indent=2)
