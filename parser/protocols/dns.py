import binascii

import dnslib
#import dnspython3

class DNSPacket:
    def __init__(self, data):
        self.data = data
        fields = self._parse()
        self.id = fields[0]
        self.qr = fields[1]
        self.opcode = fields[2]
        self.aa = fields[3]
        self.tc = fields[4]
        self.rd = fields[5]
        self.ra = fields[6]
        self.rcode = fields[7]
        self.total_questions = len(fields[8])
        self.total_answer_rrs = len(fields[9])
        self.total_authority_rrs = len(fields[10])
        self.total_additional_rrs = len(fields[11])
        self.questions = fields[8]
        self.answer_rrs = fields[9]
        self.authority_rrs = fields[10]
        self.additional_rrs = fields[11]

    def _parse(self):
        record = dnslib.DNSRecord.parse(self.data)
        #message = dnspython3.dns.message.from_wire(self.data)
        record_id = 0
        qr = record.header.get_qr()
        opcode = record.header.get_opcode()
        aa = record.header.get_aa()
        tc = record.header.get_tc()
        rd = record.header.get_rd()
        ra = record.header.get_ra()
        rcode = record.header.get_rcode()
        questions = []
        for q in record.questions:
            questions.append({"name": q.get_qname(),
                              "type": q.qtype,
                              "class": q.qclass})
        print(questions)
        answer_rrs = record.rr
        authority_rrs = record.auth
        additional_rrs = record.ar
        return (record_id, qr, opcode, aa, tc, rd, ra, rcode, questions,
                answer_rrs, authority_rrs, additional_rrs)

    def header(self):
        h = {
          "id": self.id,
          "qr": self.qr,
          "opcode": self.opcode,
          "aa": self.aa,
          "tc": self.tc,
          "rd": self.rd,
          "ra": self.ra,
          "rcode": self.rcode,
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
