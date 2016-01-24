import binascii
import struct

class UDPDatagram:
    """
    This class represents a UDP datagram.
    """

    def __init__(self, data):
        self.data = data
        fields = self._parse()

        self.source_port = fields[0]
        self.destination_port = fields[1]
        self.length = fields[2]
        self.checksum = fields[3]
        self.payload = fields[4]

    def _parse(self):
        fields = struct.unpack('!2s2s2s2s', self.data[:8])
        payload = self.data[8:]

        source_port = int(binascii.hexlify(fields[0]).decode(), 16)
        destination_port = int(binascii.hexlify(fields[1]).decode(), 16)
        length = int(binascii.hexlify(fields[2]).decode(), 16)
        checksum = "0x" + binascii.hexlify(fields[3]).decode()
        
        return (source_port, destination_port, length, checksum, payload)

    def header(self):
        h = {
          "source_port": self.source_port,
          "destination_port": self.destination_port,
          "length": self.length,
          "checksum": self.checksum,
        }
        return h

    def payload(self):
        return self.payload
