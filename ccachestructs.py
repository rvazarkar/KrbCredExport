import struct


# LB is a single byte representing the length of the rest of the section
# LT is a 3 byte structure consisting of the byte 82 followed by 2 bytes representing the length of the rest of the file

# header{
#   uint16 tag
#   uint16 taglen
#   uint8[taglen] tagdata
# }
class Header:
    def __init__(self):
        self.tag = None
        self.taglen = None
        self.deltatime = DeltaTime()

    def parsefile(self, f):
        self.tag, self.taglen = struct.unpack(">HH",f.read(4))
        self.deltatime.parsefile(f)

    def tostring(self):
        r = ''
        r += struct.pack(">HH", self.tag, self.taglen)
        r += self.deltatime.tostring()
        return r


# deltatime{
#   uint32 time_offset
#   uint32 usec_offset
# }
class DeltaTime:
    def __init__(self):
        self.usec_offset = None
        self.time_offset = None

    def parsefile(self, f):
        self.time_offset, self.usec_offset = struct.unpack(">LL",f.read(8))

    def tostring(self):
        r = ''
        r += struct.pack(">LL", self.time_offset, self.usec_offset)
        return r


# ccacheheader{
#   uint16 version
#   uint16 header_len
#   header[] headers
#   principal primary_principal
# }
class CCacheHeader:
    def __init__(self):
        self.version = None
        self.header_length = None
        self.header = Header()

    def parsefile(self, f):
        self.version, = struct.unpack(">H", f.read(2))
        self.header_length, = struct.unpack(">H", f.read(2))
        self.header.parsefile(f)

    def tostring(self):
        r = ''
        r += struct.pack(">HH", self.version, self.header_length)
        r += self.header.tostring()
        return r


# times{
#   uint32 authtime
#   uint32 starttime
#   uint32 endtime
#   uint32 renew_till
# }
class KerbTimes:
    def __init__(self):
        self.authtime = None
        self.starttime = None
        self.endtime = None
        self.renew_till = None

    def parsefile(self, f):
        self.authtime, self.starttime, self.endtime, self.renew_till = struct.unpack(">IIII", f.read(16))

    def tostring(self):
        return struct.pack(">IIII",self.authtime, self.starttime, self.endtime, self.renew_till)


# counted_octet{
#   uint32 length
#   uint8[char] data
# }
class CountedOctet:
    def __init__(self):
        self.length = None
        self.data = None

    def parsefile(self, f):
        self.length, = struct.unpack(">L",f.read(4))
        self.data, = struct.unpack(">%ds" % self.length ,f.read(self.length))

    def tostring(self):
        r = b''
        r += struct.pack(">L", self.length)
        r += struct.pack(">%ds" % self.length, self.data)
        return r


# keyblock{
#   uint16 keytype
#   uint16 etype
#   uint16 keylen
#   uint8[keylen] key
# }
class Keyblock:
    def __init__(self):
        self.keytype = None
        self.etype = None
        self.keylen = None
        self.key = None

    def parsefile(self, f):
        self.keytype, self.etype, self.keylen = struct.unpack(">HHH",f.read(6))
        self.key, = struct.unpack(">%ds" % self.keylen, f.read(self.keylen))

    def tostring(self):
        r = ''
        r += struct.pack(">HHH", self.keytype, self.etype, self.keylen)
        r += struct.pack(">%ds" % self.keylen, self.key)
        return r


# principal{
#   uint32 name_type
#   uint32 num_components
#   counted_octet realm
#   counted_octet[num_components] components
# }
class Principal:
    def __init__(self):
        self.name_type = None
        self.num_components = None
        self.realm = CountedOctet()
        self.components = []

    def parsefile(self, f):
        self.name_type, self.num_components = struct.unpack(">LL", f.read(8))
        self.realm.parsefile(f)
        for i in xrange(0, self.num_components):
            component = CountedOctet()
            component.parsefile(f)
            self.components.append(component.data)

    def tostring(self):
        r = ''
        r += struct.pack(">LL", self.name_type, self.num_components)
        r += self.realm.tostring()
        for i in self.components:
            r += struct.pack(">L", len(i))
            r += i
        return r


# address{
#   uint16 address_type
#   counted_octet address
# }
class Address:
    def __init__(self):
        self.address_type = None
        self.address = CountedOctet()

    def parsefile(self, f):
        self.address_type, = struct.unpack(">H", f.read(2))
        self.address.parsefile(f)

    def tostring(self):
        r = ''
        r += struct.pack(">H", self.address_type)
        r += self.address.tostring()
        return r


# authdata{
#   uint16 authtype
#   counted_octet authdata
# }
class AuthData:
    def __init__(self):
        self.authtype = None
        self.authdata = CountedOctet()

    def parsefile(self, f):
        self.authtype, = struct.unpack(">H", f.read(2))
        self.authdata.parsefile(f)

    def tostring(self):
        r = ''
        r += struct.pack(">H", self.authtype)
        r += self.authdata.tostring()
        return r


# credential{
#   principal client
#   principal server
#   keyblock key
#   times timedata
#   uint8 skey
#   uint32 tktFlags (Reverse Byte Order!)
#   uint32 num_address
#   address[num_address] addresses
#   uint32 num_authdata
#   authdata[num_authdata] auths
#   counted_octet ticket_1
#   counted_octet ticket_2 (nothing here in what I've seen)
# }
class Credential:
    def __init__(self):
        self.client = Principal()
        self.server = Principal()
        self.keyblock = Keyblock()
        self.times = KerbTimes()
        self.is_skey = None
        self.tktFlags = None
        self.num_address = None
        self.address = []
        self.num_authdata = None
        self.authdata = []
        self.ticket = CountedOctet()
        self.secondticket = CountedOctet()

    def parsefile(self, f):
        self.client.parsefile(f)
        self.server.parsefile(f)
        self.keyblock.parsefile(f)
        self.times.parsefile(f)
        self.is_skey, = struct.unpack(">B", f.read(1))
        self.tktFlags, = struct.unpack("<I", f.read(4))
        self.num_address, = struct.unpack(">I", f.read(4))
        for i in xrange(0, self.num_address):
            self.address.append(Address().parsefile(f))
        self.num_authdata, = struct.unpack(">I", f.read(4))
        for i in xrange(0, self.num_authdata):
            self.authdata.append(AuthData().parsefile(f))
        self.ticket.parsefile(f)
        self.secondticket.parsefile(f)

    def tostring(self):
        r = ''
        r += self.client.tostring()
        r += self.server.tostring()
        r += self.keyblock.tostring()
        r += self.times.tostring()
        r += struct.pack(">B", self.is_skey)
        r += struct.pack("<I", self.tktFlags)
        r += struct.pack(">I", self.num_address)
        for i in self.address:
            r += i.tostring()
        r += struct.pack(">I", self.num_authdata)
        for i in self.authdata:
            r += i.tostring()
        r += self.ticket.tostring()
        r += self.secondticket.tostring()
        return r
