import binascii
import struct

class EthernetFrame:
    """
    This class represents an Ethernet frame.
    """

    def __init__(self, data):
        self.data = data
        fields = self._parse()

        self.type = fields[0]
        self.source_address = fields[1]
        self.destination_address = fields[2]
        self.payload = fields[3]

    def _parse(self):
        fields = struct.unpack('!6s6s2s', self.data[:14])
        payload = self.data[14:]

        dest_address = ':'.join(["{0:0>2x}".format(b) for b in fields[0]])
        src_address = ':'.join(["{0:0>2x}".format(b) for b in fields[1]])
        eth_type = "0x" + binascii.hexlify(fields[2]).decode()
        
        return (eth_type, src_address, dest_address, payload)

    def header(self):
        h = {
            "type": self.type,
            "source_address": self.source_address,
            "destination_address": self.destination_address,
        }
        return h

    def payload(self):
        return self.payload
