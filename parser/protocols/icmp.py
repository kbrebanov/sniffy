import binascii
import struct

class ICMPPacket:
    def __init__(self, data):
        self.data = data
        fields = self._parse()
        self.type = fields[0]
        self.code = fields[1]
        self.checksum = fields[2]
        self.payload = fields[3]

    def _parse(self):
        fields = struct.unpack('!1s1s2s', self.data[:4])
        payload = self.data[4:]
        icmp_type = int(binascii.hexlify(fields[0]).decode(), 16)
        code = int(binascii.hexlify(fields[1]).decode(), 16)
        checksum = "0x" + binascii.hexlify(fields[2]).decode()
        return (icmp_type, code, checksum, payload)

    def header(self):
        h = {
          "type": self.type,
          "code": self.code,
          "checksum": self.checksum,
          "data": self.payload,
        }
        return h
