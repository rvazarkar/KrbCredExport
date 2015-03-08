import struct
import datetime


# Prepend, shortened for convenience
def p(a, b):
    return b + a


# Returns the length of s as a single byte
def clen(s):
    return chr(len(s))


# LB is a single byte representing the length of the rest of the section
# LT is a 3 byte structure consisting of the byte 82 followed by 2 bytes representing the length of the rest of the file


# key{
#   0xA0 LB
#   0x30 LB
#   0xA0 0x03 0x02 0x01
#   uint8 key_type
#   0xA1 LB
#   0x03 LB
#   keydata
# }
class Key:

    def __init__(self):
        self.key = None
        self.keytype = None

    def parsefile(self, f):
        f.read(8)
        self.keytype, = struct.unpack('>B', f.read(1))
        f.read(3)
        keylen, = struct.unpack('>B', f.read(1))
        self.key, = struct.unpack(">%ds" % keylen, f.read(keylen))

    def tostring(self):
        r = ''
        r += self.key
        r = p(r, clen(r))
        r = p(r, '\x04')
        r = p(r, clen(r))
        r = p(r, '\xA1')
        r = p(r, chr(self.keytype))
        r = p(r, '\xA0\x03\x02\x01')
        r = p(r, clen(r))
        r = p(r, '\x30')
        r = p(r, clen(r))
        r = p(r, '\xA0')
        return r


# This section represents the primary principal realm. Corresponds to the domain name
# prealm{
#   0xA1 LB
#   0x1B LB
#   Primary Principal Realm
# }
class PRealm:

    def __init__(self):
        self.principal_realm = None

    def parsefile(self, f):
        f.read(3)
        length, = struct.unpack(">b", f.read(1))
        self.principal_realm, = struct.unpack(">%ds" % length, f.read(length))

    def tostring(self):
        r = ''
        r += self.principal_realm
        r = p(r, clen(r))
        r = p(r, '\x1B')
        r = p(r, clen(r))
        r = p(r, '\xA1')
        return r


# This section represents the primary principal realm
# pname{
#   0xA2 LB
#   0x30 LB
#   0xA0 0x03 0x02 0x01
#   uint8 name_type
#   0xA1 LB
#   0x30 LB
#   0x1B LB
#   Primary Principal Name
# }
class PName:

    def __init__(self):
        self.principal_components = []
        self.principal_name_type = None

    def parsefile(self, f):
        f.read(8)
        self.principal_name_type, = struct.unpack(">B", f.read(1))
        f.read(3)
        rem_length, = struct.unpack(">B", f.read(1))
        while (rem_length > 0):
            f.read(1)
            l, = struct.unpack(">B", f.read(1))
            component, = struct.unpack("%ds" % l, f.read(l))
            self.principal_components.append(component)
            rem_length -= (2 + l)

    def tostring(self):
        r = ''
        for s in self.principal_components:
            r += '\x1B' + chr(len(s)) + s
        r = p(r, clen(r))
        r = p(r, '\x30')
        r = p(r, clen(r))
        r = p(r, '\xA1')
        r = p(r, chr(self.principal_name_type))
        r = p(r, '\xA0\x03\x02\x01')
        r = p(r, clen(r))
        r = p(r, '\x30')
        r = p(r, clen(r))
        r = p(r, '\xA2')
        return r


# This section details flags for the ticket
# tktflags{
#   0xA3 LB
#   0x03 LB
#   0x00 Always 0, apparently number of unused bytes. tktFlags is always a uint32
#   uint32 Ticket Flags
# }
class TicketFlags:

    def __init__(self):
        self.ticket_flags = None

    def parsefile(self, f):
        f.read(5)
        self.ticket_flags, = struct.unpack("I", f.read(4))

    def tostring(self):
        r = ''
        r += struct.pack("I", self.ticket_flags)
        r = p(r, '\x00')
        r = p(r, clen(r))
        r = p(r, '\x03')
        r = p(r, clen(r))
        r = p(r, '\xA3')
        return r


# These sections contain the ticket timestamps. Note that the timestamps are in a consistent format, so length tags are always the same
# Timestamp format is YYYYmmddHHMMSSZ and must be UTC!
# 0xA5 is starttime, 0xA6 is endtime, 0xA7 is renew_till
# time{
#   uint8 Identifier
#   LB (Always 0x11)
#   0x18 LB (Always 0x0F)
#   start_time
# }
class Time:

    def __init__(self, identifier):
        self.identifier = identifier
        self.time = None

    @staticmethod
    def convert_to_unix(timestr):
        epoch = datetime.datetime(1970, 1, 1)
        t = datetime.datetime.strptime(timestr[:-1], '%Y%m%d%H%M%S')
        td = t - epoch
        return int((td.microseconds + (td.seconds + td.days * 24 * 3600) * 10 ** 6) / 1e6)

    @staticmethod
    def convert_to_kerbtime(unixtime):
        t = datetime.datetime.utcfromtimestamp(unixtime)
        t = ''.join([t.strftime('%Y'), t.strftime('%m'), t.strftime('%d'),
                     t.strftime('%H'), t.strftime('%M'), t.strftime('%S'), 'Z'])
        return t

    def parsefile(self, f):
        self.identifier, = struct.unpack(">B", f.read(1))
        f.read(3)
        strtime, = struct.unpack(">15s", f.read(15))
        self.time = Time.convert_to_unix(strtime)

    def tostring(self):
        r = ''
        r += struct.pack(">15s", Time.convert_to_kerbtime(self.time))
        r = p(r, '\x11\x18\x0F')
        r = p(r, chr(self.identifier))
        return r


# This section represents the server realm (domain)
# srealm{
#   0xA8 LB
#   0x1B LB
#   server_realm (domain name of server)
# }
class SRealm:

    def __init__(self):
        self.server_realm = None

    def parsefile(self, f):
        f.read(3)
        length, = struct.unpack(">B", f.read(1))
        self.server_realm, = struct.unpack(">%ds" % length, f.read(length))

    def tostring(self):
        r = ''
        r += self.server_realm
        r = p(r, clen(r))
        r = p(r, '\x1B')
        r = p(r, clen(r))
        r = p(r, '\xA8')
        return r


# This section represents the server name components
# sname{
#   0xA9 LB
#   0x30 LB
#   0xA0 0x03 0x02 0x01
#   uint8 server_name_type
#   0xA1 LB
#   0x30 LB
#   components[]
# }
#
# components{
#   0x1B
#   uint8 Component Length
#   Component
# }

class SName:

    def __init__(self):
        self.server_components = []
        self.server_name_type = None

    def parsefile(self, f):
        f.read(8)
        self.server_name_type, = struct.unpack(">B", f.read(1))
        f.read(3)
        rem_length, = struct.unpack(">B", f.read(1))
        while rem_length > 0:
            f.read(1)
            l, = struct.unpack(">B", f.read(1))
            component, = struct.unpack(">%ds" % l, f.read(l))
            self.server_components.append(component)
            rem_length -= (2 + l)

    def tostring(self):
        r = ''
        for s in self.server_components:
            r += '\x1B' + chr(len(s)) + s
        r = p(r, clen(r))
        r = p(r, '\x30')
        r = p(r, clen(r))
        r = p(r, '\xA1')
        r = p(r, chr(self.server_name_type))
        r = p(r, '\xA0\x03\x02\x01')
        r = p(r, clen(r))
        r = p(r, '\x30')
        r = p(r, clen(r))
        r = p(r, '\xA9')
        return r


# header{
#   0x7D LT
#   0x30 LT
#   0xA0 LT
#   0x30 LT
#   0x30 LT
# }
class KrbCredInfo:

    def __init__(self):
        self.krbcredinfo = None
        self.key = Key()
        self.prealm = PRealm()
        self.pname = PName()
        self.flags = TicketFlags()
        self.starttime = Time(165)
        self.endtime = Time(166)
        self.renew_till = Time(167)
        self.srealm = SRealm()
        self.sname = SName()

    def parsefile(self, f):
        f.read(20)
        self.key.parsefile(f)
        self.prealm.parsefile(f)
        self.pname.parsefile(f)
        self.flags.parsefile(f)
        self.starttime.parsefile(f)
        self.endtime.parsefile(f)
        self.renew_till.parsefile(f)
        self.srealm.parsefile(f)
        self.sname.parsefile(f)
        self.krbcredinfo = self.key.tostring() + self.prealm.tostring() + self.pname.tostring() + self.flags.tostring() + \
            self.starttime.tostring() + self.endtime.tostring() + \
            self.renew_till.tostring() + self.srealm.tostring() + \
            self.sname.tostring()

    def tostring(self):
        r = self.krbcredinfo
        r = p(r, struct.pack(">H", len(r)))
        r = p(r, '\x30\x82')
        r = p(r, struct.pack(">H", len(r)))
        r = p(r, '\x30\x82')
        r = p(r, struct.pack(">H", len(r)))
        r = p(r, '\xA0\x82')
        r = p(r, struct.pack(">H", len(r)))
        r = p(r, '\x30\x82')
        r = p(r, struct.pack(">H", len(r)))
        r = p(r, '\x7D\x82')
        return r

    def createkrbcrdinfo(self):
        self.krbcredinfo = self.key.tostring() + self.prealm.tostring() + self.pname.tostring() + self.flags.tostring() + \
            self.starttime.tostring() + self.endtime.tostring() + \
            self.renew_till.tostring() + self.srealm.tostring() + \
            self.sname.tostring()
