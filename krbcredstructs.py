import struct
import krbcredinfostructs as kc


# LB is a single byte representing the length of the rest of the section
# LT is a 3 byte structure consisting of the byte 82 followed by 2 bytes representing the length of the rest of the file

def p(a, b):
    return b + a


# The encpart serves as a sort of header for the EncKrbCredPart
# encpart{
#   0xA0 0x03 0x02 0x01
#   uint8 etype (Seems to always be 0 in my testing)
#   0xA2 LT
#   0x04 LT
# }
class EncPart:
    def __init__(self):
        self.krbcredinfo = kc.KrbCredInfo()
        self.etype = None

    def parsefile(self, f):
        f.read(4)
        self.etype, = struct.unpack(">B", f.read(1))
        f.read(8)
        self.krbcredinfo.parsefile(f)

    def tostring(self):
        r = self.krbcredinfo.tostring()
        r = p(r, struct.pack(">H", len(r)))
        r = p(r, '\x04\x82')
        r = p(r, struct.pack(">H", len(r)))
        r = p(r, '\xA2\x82')
        r = p(r, chr(self.etype))
        r = p(r, '\xA0\x03\x02\x01')
        return r


# This section represents the tickets section of the overall KrbCred
# tickets{
#   0xA2 0x82
#   uint16 ticket_length + 4
#   0x30 0x82
#   uint16 ticket_length
#   ticket
#   0xA3 LT
#   0x30 LT
# }
class TicketPart:
    def __init__(self):
        self.ticket = None
        self.encpart = EncPart()

    def parsefile(self, f):
        f.read(6)
        ticketlen, = struct.unpack(">H", f.read(2))
        self.ticket, = struct.unpack(">%ds" % ticketlen, f.read(ticketlen))
        f.read(8)
        self.encpart.parsefile(f)

    def tostring(self):
        r = self.encpart.tostring()
        r = p(r, struct.pack(">H", len(r)))
        r = p(r, '\x30\x82')
        r = p(r, struct.pack(">H", len(r)))
        r = p(r, '\xA3\x82')
        r = p(r, self.ticket)
        r = p(r, struct.pack(">H", len(self.ticket)))
        r = p(r, '\x30\x82')
        r = p(r, struct.pack(">H", len(self.ticket) + 4))
        r = p(r, '\xA2\x82')
        return r


# This is the header for the kerberos ticket, and the final section
# header{
#   0x76 LT
#   0x30 LT
#   0xA0 0x03 0x02 0x01
#   uint8 pvno (Protocol Version, always 0x05)
#   0xA1 0x03 0x02 0x01
#   uint8 msg-type (Always 0x16 for krbcred)
# }
class KrbCredHeader:
    def __init__(self):
        self.ticketpart = TicketPart()

    def parsefile(self, f):
        f.read(18)
        self.ticketpart.parsefile(f)

    def tostring(self):
        r = self.ticketpart.tostring()
        r = p(r, '\xA1\x03\x02\x01\x16')
        r = p(r, '\xA0\x03\x02\x01\x05')
        r = p(r, struct.pack(">H", len(r)))
        r = p(r, '\x30\x82')
        r = p(r, struct.pack(">H", len(r)))
        r = p(r, '\x76\x82')
        return r
