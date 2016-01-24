import sys
import binascii

import dns.message
import dns.exception

class DNSPacket:
    """
    This class represents a DNS packet.
    """
    def __init__(self, data):
        self.data = data
        fields = self._parse()
        
        self.id = fields[0]
        self.flags = fields[1]
        self.total_questions = fields[2]
        self.total_answer_rrs = fields[3]
        self.total_authority_rrs = fields[4]
        self.total_additional_rrs = fields[5]
        self.questions = fields[6]
        self.answer_rrs = fields[7]
        self.authority_rrs = fields[8]
        self.additional_rrs = fields[9]

    def _parse(self):
        try:
            message = dns.message.from_wire(self.data)
        except dns.exception.ShortHeader:
            print("The message is less than 12 octets long.", file=sys.stderr)
            raise
        except dns.exception.TrailingJunk:
            print("There were octets in the message past the end of the proper DNS message.",
                  file=sys.stderr)
            raise
        except dns.exception.BadEDNS:
            print("An OPT record was in the wrong section, or occurred more than once.",
                  file=sys.stderr)
            raise
        except dns.exception.BadTSIG:
            print("A TSIG record was not the last record of the additional data section.",
                  file=sys.stderr)
            raise

        message_id = message.id

        flags = {}
        if (message.flags & 32768) == 32768:
            flags["qr"] = 1
        else:
            flags["qr"] = 0
        flags["opcode"] = message.opcode()
        if (message.flags & 1024) == 1024:
            flags["aa"] = 1
        else:
            flags["aa"] = 0
        if (message.flags & 512) == 512:
            flags["tc"] = 1
        else:
            flags["tc"] = 0
        if (message.flags & 256) == 256:
            flags["rd"] = 1
        else:
            flags["rd"] = 0
        if (message.flags & 128) == 128:
            flags["ra"] = 1
        else:
            flags["ra"] = 0
        if (message.flags & 64) == 64:
            flags["z"] = 1
        else:
            flags["z"] = 0
        if (message.flags & 32) == 32:
            flags["ad"] = 1
        else:
            flags["ad"] = 0
        if (message.flags & 16) == 16:
            flags["cd"] = 1
        else:
            flags["cd"] = 0
        flags["rcode"] = message.rcode()

        total_questions = len(message.question)
        total_answer_rrs = len(message.answer)
        total_authority_rrs = len(message.authority)
        total_additional_rrs = len(message.additional)

        questions = []
        for question in message.question:
            questions.append({"name": question.name.to_text(),
                              "type": question.rdtype,
                              "class": question.rdclass})
        answer_rrs = []
        for answer in message.answer:
            rdata_items = []
            for item in answer.items:
                rdata_items.append(item.to_text())

            answer_rrs.append({"name": answer.name.to_text(),
                               "type": answer.rdtype,
                               "class": answer.rdclass,
                               "ttl": answer.ttl,
                               "rdata_length": len(answer.items),
                               "rdata": rdata_items})

        authority_rrs = []
        for authority in message.authority:
            rdata_items = []
            for item in authority.items:
                rdata_items.append(item.to_text())

            authority_rrs.append({"name": authority.name.to_text(),
                                  "type": authority.rdtype,
                                  "class": authority.rdclass,
                                  "ttl": authority.ttl,
                                  "rdata_length": len(authority.items),
                                  "rdata": rdata_items})

        additional_rrs = []
        for additional in message.additional:
            rdata_items = []
            for item in additional.items:
                rdata_items.append(item.to_text())

            additional_rrs.append({"name": additional.name.to_text(),
                                   "type": additional.rdtype,
                                   "class": additional.rdclass,
                                   "ttl": additional.ttl,
                                   "rdata_length": len(additional.items),
                                   "rdata": rdata_items})

        return (message_id, flags, total_questions, total_answer_rrs,
                total_authority_rrs, total_additional_rrs, questions,
                answer_rrs, authority_rrs, additional_rrs)

    def header(self):
        h = {
          "id": self.id,
          "flags": self.flags,
          "total_questions": self.total_questions,
          "total_answer_rrs": self.total_answer_rrs,
          "total_authority_rrs": self.total_authority_rrs,
          "total_additional_rrs": self.total_additional_rrs,
          "questions": self.questions,
          "answer_rrs": self.answer_rrs,
          "auhtority_rrs": self.authority_rrs,
          "additional_rrs": self.additional_rrs,
        }
        return h

    def payload(self):
        pass
