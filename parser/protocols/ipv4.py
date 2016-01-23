import binascii
import struct

class IPv4Packet:
    def __init__(self, data):
        self.data = data
        fields = self._parse()
        self.version = fields[0]
        self.header_length = fields[1]
        self.dscp = fields[2]
        self.ecn = fields[3]
        self.total_length = fields[4]
        self.identification = fields[5]
        self.flags = fields[6]
        self.fragment_offset = fields[7]
        self.ttl = fields[8]
        self.protocol = fields[9]
        self.header_checksum = fields[10]
        self.source_address = fields[11]
        self.destination_address = fields[12]
        self.options = fields[13]
        self.payload = fields[14]

    def _parse(self):
        fields = struct.unpack('!1s1s2s2s2s1s1s2s4s4s', self.data[:20])
        payload = self.data[20:]
        version = int(binascii.hexlify(fields[0]).decode()[0], 16)
        header_length = int(binascii.hexlify(fields[0]).decode()[1], 16)
        dscp = int(binascii.hexlify(fields[1]).decode(), 16) >> 2
        ecn = int(binascii.hexlify(fields[1]).decode(), 16) & 3
        total_length = int(binascii.hexlify(fields[2]).decode(), 16)
        identification = "0x" + binascii.hexlify(fields[3]).decode()
        flags = int(binascii.hexlify(fields[4]).decode(), 16) & 57344
        set_flags = []
        if flags & 2 == 2:
            set_flags.append("DF")
        if flags & 1 == 1:
            set_flags.append("MF")
        fragment_offset = int(binascii.hexlify(fields[4]).decode(), 16) & 8191
        ttl = int(binascii.hexlify(fields[5]).decode(), 16)
        protocol = int(binascii.hexlify(fields[6]).decode(), 16)
        header_checksum = "0x" + binascii.hexlify(fields[7]).decode()
        source_address = '.'.join(["{0:d}".format(b) for b in fields[8]])
        destination_address = '.'.join(["{0:d}".format(b) for b in fields[9]])
        options = ''
        if header_length > 5:
            options = struct.unpack('!4s', payload[:4])
            payload = self.data[24:]
        return (version, header_length, dscp, ecn, total_length,
               identification, set_flags, fragment_offset, ttl, protocol,
               header_checksum, source_address, destination_address,
               options, payload)

    def header(self):
        h = {
            "version": self.version,
            "header_length": self.header_length,
            "dscp": self.dscp,
            "ecn": self.ecn,
            "total_length": self.total_length,
            "identification": self.identification,
            "flags": self.flags,
            "fragment_offset": self.fragment_offset,
            "ttl": self.ttl,
            "protocol": self.protocol,
            "header_checksum": self.header_checksum,
            "source_address": self.source_address,
            "destination_address": self.destination_address,
            "options": self.options,
        }
        return h

    def payload(self):
        return self.payload
