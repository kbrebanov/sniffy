import binascii
import struct

class TCPSegment:
    """
    This class represents a TCP segment.
    """

    def __init__(self, data):
        self.data = data
        fields = self._parse()

        self.source_port = fields[0]
        self.destination_port = fields[1]
        self.sequence_number = fields[2]
        self.ack_number = fields[3]
        self.data_offset = fields[4]
        self.flags = fields[5]
        self.window_size = fields[6]
        self.checksum = fields[7]
        self.urgent_pointer = fields[8]
        self.options = fields[9]
        self.payload = fields[10]

    def _parse(self):
        fields = struct.unpack('!2s2s4s4s1s1s2s2s2s', self.data[:20])
        payload = self.data[20:]

        source_port = int(binascii.hexlify(fields[0]).decode(), 16)
        destination_port = int(binascii.hexlify(fields[1]).decode(), 16)
        sequence_number = int(binascii.hexlify(fields[2]).decode(), 16)
        ack_number = int(binascii.hexlify(fields[3]).decode(), 16)
        data_offset = int(binascii.hexlify(fields[4]).decode()[0], 16)
        reserved_ns = int(binascii.hexlify(fields[4]).decode()[1], 16)

        flags = int(binascii.hexlify(fields[5]).decode(), 16)
        set_flags = []
        if reserved_ns & 1 == 1:
            set_flags.append("NS")
        if flags & 128 == 128:
            set_flags.append("CWR")
        if flags & 64 == 64:
            set_flags.append("ECE")
        if flags & 32 == 32:
            set_flags.append("URG")
        if flags & 16 == 16:
            set_flags.append("ACK")
        if flags & 8 == 8:
            set_flags.append("PSH")
        if flags & 4 == 4:
            set_flags.append("RST")
        if flags & 2 == 2:
            set_flags.append("SYN")
        if flags & 1 == 1:
            set_flags.append("FIN")

        window_size = int(binascii.hexlify(fields[6]).decode(), 16)
        checksum = "0x" + binascii.hexlify(fields[7]).decode()
        urgent_pointer = "0x" + binascii.hexlify(fields[8]).decode()

        options = ''
        if data_offset > 5:
            options = struct.unpack('!4s', payload[:4])
            payload = self.data[24:]
            
        return (source_port, destination_port, sequence_number, ack_number,
               data_offset, set_flags, window_size, checksum, urgent_pointer,
               options, payload)

    def header(self):
        h = {
          "source_port": self.source_port,
          "destination_port": self.destination_port,
          "sequence_number": self.sequence_number,
          "ack_number": self.ack_number,
          "data_offset": self.data_offset,
          "flags": self.flags,
          "window_size": self.window_size,
          "checksum": self.checksum,
          "urgent_pointer": self.urgent_pointer,
          "options": self.options,
        }
        return h

    def payload(self):
        return self.payload
