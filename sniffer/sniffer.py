import threading

import pcappy
import parser.packet as packet_parser

MAX_PACKET_SIZE=65535
TIMEOUT=1000

class Sniffer(threading.Thread):
    def __init__(self, interface, snaplen, promisc, ms):
        threading.Thread.__init__(self)
        self.interface = interface
        self.snaplen = snaplen
        self.promisc = promisc
        self.ms = ms
        self.d = {}
        self.capture = None

    def run(self):
        self.capture = pcappy.open_live(self.interface, snaplen=self.snaplen,
                                        promisc=self.promisc, to_ms=self.ms)
        self.capture.loop(-1, self._parse_packet, self.d)

    def stop(self):
        self.capture.breakloop()

    def _parse_packet(self, d, hdr, data):
        ts = float(str(hdr.ts[1]) + "." + str(hdr.ts[0]))
        packet = packet_parser.Packet(ts, data)
        if packet:
            print(packet.to_json())
