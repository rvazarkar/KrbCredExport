#!/usr/bin/env python

import sys
import struct
import binascii
import datetime

version = ''
seqtag = '\x30'
lentag = '\x82'


class TicketData:
    # This is all the data needed to generate the ticket that's pulled from the CCache file.
    def __init__(self):
        self.ticket = None
        self.server_components = None
        self.server_realm = None
        self.server_name_type = None
        self.key = None
        self.keytype = None
        self.ticket_flags = None
        self.starttime = None
        self.endtime = None
        self.renew_till = None
        self.principal_realm = None
        self.principal_components = None
        self.principal_name_type = None
        self.etype = None

    def convert_timestamp(self, timestamp):
        # Convert Unix Timestamps to the kerberos timestamp format
        t = datetime.datetime.utcfromtimestamp(timestamp)
        t = ''.join([t.strftime('%Y'),t.strftime('%m'), t.strftime('%d'), t.strftime('%H'), t.strftime('%M'), t.strftime('%S'), 'Z'])
        return t

    def set_server(self, server):
        self.server_realm = server[0]
        self.server_components = server[1]
        self.server_name_type = server[2]

    def set_key(self, key, keytype, etype):
        self.key = key
        self.keytype = keytype
        self.etype = etype

    def set_times(self, starttime, endtime, renew_till):
        self.starttime = self.convert_timestamp(starttime)
        self.endtime = self.convert_timestamp(endtime)
        self.renew_till = self.convert_timestamp(renew_till)

    def set_ticket_flags(self, flags):
        self.ticket_flags = flags

    def set_principal(self, principal):
        self.principal_realm = principal[0]
        self.principal_components = principal[1]
        self.principal_name_type = principal[2]

    def set_ticket(self, ticket):
        self.ticket = ticket


# These functions represent different structures in the original ccache file
# times{
#   uint32 authtime
#   uint32 starttime
#   uint32 endtime
#   uint32 renew_till    
# }
def create_times(f):
    authtime, starttime, endtime, renew_till = struct.unpack(">IIII", f.read(16))
    return authtime, starttime, endtime, renew_till

# counted_octet{
#   uint32 length
#   uint8[char] data    
# }
def create_counted_octet(f):
    length, = struct.unpack(">L",f.read(4))
    string =  ">" + ("c" * length)
    a = f.read(length)
    data = struct.unpack(string,a)
    return (length,data)

# principal{
#   uint32 name_type
#   uint32 num_components
#   counted_octet realm
#   counted_octet[num_components] components    
# }
def create_principal(f):
    name_type, num_components = struct.unpack(">LL", f.read(8))
    realm = create_counted_octet(f)
    realmname = ''.join(realm[1])
    components = []
    for i in xrange(0,num_components):
        component = create_counted_octet(f)
        components.append(''.join(component[1]))
    return realmname, components, name_type

# keyblock{
#   uint16 keytype
#   uint16 etype
#   uint16 keylen
#   uint8[keylen] key       
# }
def create_keyblock(f):
    keytype, etype, keylen = struct.unpack(">HHH",f.read(6))
    string = ">" + ("c" * keylen)
    data = struct.unpack(string,f.read(keylen))
    return keylen, data, keytype, etype

# address{
#   uint16 address_type
#   counted_octet address    
# }
def create_address(f):
    addrtype = struct.unpack(">H",f.read(2))
    create_counted_octet(f)

# authdata{
#   uint16 authtype
#   counted_octet authdata    
# }
def create_authdata(f):
    authtype = struct.unpack(">H",f.read(2))
    create_counted_octet(f)

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
def create_credential(f, ticket_data):
    client = create_principal(f)
    server = create_principal(f)
    keylen, key, keytype, etype = create_keyblock(f)
    authtime, starttime, endtime, renew_till = create_times(f)
    is_skey, = struct.unpack(">B",f.read(1))
    tktFlags, = struct.unpack("<I", f.read(4))
    num_address, = struct.unpack(">I",f.read(4))
    for i in xrange(0,num_address):
        create_address(f)
    num_authdata, = struct.unpack(">I",f.read(4))
    for i in xrange(0,num_authdata):
        create_authdata(f)
    ticket = create_counted_octet(f)
    secondticket = create_counted_octet(f)

    ticket_data.set_server(server)
    ticket_data.set_key(key, keytype, etype)
    ticket_data.set_times(starttime, endtime, renew_till)
    ticket_data.set_ticket_flags(tktFlags)
    ticket_data.set_ticket(''.join(ticket[1]))

    return ticket_data

def prepend(a,b):
    return b + a

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "Usage: {0} <input file> <output file>".format(sys.argv[0])
        sys.exit(0)

    with open(sys.argv[1],'rb') as f:
        ticket_data = TicketData()
        version, = struct.unpack(">H",f.read(2))
        if version == 0x504:
            print 'Version 0504 Found'
        else:
            print 'Wrong CCache Version to Export, required version is 504!'
            sys.exit(0)


        print 'Parsing CCache Data'
        headerlength, = struct.unpack(">H",f.read(2))
        header = struct.unpack(">HH",f.read(4))
        if header[0] == 1:
            time_offset,usec_offset = struct.unpack(">LL",f.read(8))
        principal = create_principal(f)
        ticket_data.set_principal(principal)
        #Done with the headers, on to cool stuff!
        ticket_data = create_credential(f, ticket_data)

    with open(sys.argv[2],'wb') as ticket:
        # The kerberos ticket references remaining size of file multiple times, so we're going to build the ticket backwards
        # Doing this let's us calculate the size of remaining portions and insert the values necessary
        # LB is a single byte representing the length of the rest of the section
        # LT is a 3 byte structure consisting of the byte 82 followed by 2 bytes representing the length of the rest of the file
        print 'Creating .kirbi file'

        # The last section of the Kerberos ticket is the enckrbcredpart, along with the encpart header.
        # All of the structs here refer to the length of each individual struct, so we can build these in order! 

        # This section represents the key embedded in the ticket
        # key{
        #   0xA0 LB
        #   0x30 LB
        #   0xA0 0x03 0x02 0x01
        #   uint8 key_type
        #   0xA1 LB
        #   0x03 LB
        #   keydata
        #}
        keytag = ''
        keytag += ''.join(ticket_data.key)
        keytag = prepend(keytag, chr(len(keytag)))
        keytag = prepend(keytag, '\x04')
        keytag = prepend(keytag, chr(len(keytag)))
        keytag = prepend(keytag, '\xA1')
        keytag = prepend(keytag, '\xA0\x03\x02\x01' + chr(ticket_data.keytype))
        keytag = prepend(keytag, chr(len(keytag)))
        keytag = prepend(keytag, seqtag)
        keytag = prepend(keytag, chr(len(keytag)))
        keytag = prepend(keytag, '\xA0')

        # This section represents the primary principal realm. Corresponds to the domain name
        # prealm{
        #   0xA1 LB
        #   0x1B LB 
        #   Primary Principal Realm
        #}
        prealmtag = b''
        prealmtag += ticket_data.principal_realm
        prealmtag = prepend(prealmtag, chr(len(prealmtag)))
        prealmtag = prepend(prealmtag, '\x1B')
        prealmtag = prepend(prealmtag, chr(len(prealmtag)))
        prealmtag = prepend(prealmtag, '\xA1')
        
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
        pnametag = b""
        pnametag += ticket_data.principal_components[0]
        pnametag = prepend(pnametag, chr(len(pnametag)))
        pnametag = prepend(pnametag, '\x1B')
        pnametag = prepend(pnametag, chr(len(pnametag)))
        pnametag = prepend(pnametag, seqtag)
        pnametag = prepend(pnametag, chr(len(pnametag)))
        pnametag = prepend(pnametag, '\xA1')
        pnametag = prepend(pnametag, '\xA0\x03\x02\x01' + chr(ticket_data.principal_name_type))
        pnametag = prepend(pnametag, chr(len(pnametag)))
        pnametag = prepend(pnametag, seqtag)
        pnametag = prepend(pnametag, chr(len(pnametag)))
        pnametag = prepend(pnametag, '\xA2')
        
        # This section details flags for the ticket
        # tktflags{
        #   0xA3 LB
        #   0x03 LB
        #   uint32 Ticket Flags
        #   0x00 (I have no idea where this byte came from!)
        # }
        flags = b"\x00"
        flags = prepend(flags,struct.pack(">I",ticket_data.ticket_flags))
        flags = prepend(flags, chr(len(flags)))
        flags = prepend(flags, '\x03')
        flags = prepend(flags, chr(len(flags)))
        flags = prepend(flags, '\xA3')

        # These sections contain the ticket timestamps. Note that the timestamps are in a consistent format, so length tags are always the same
        # Timestamp format is YYYYmmddHHMMSSZ and must be UTC!
        
        # starttime{
        #   0xA5 LB (Always 0x11)
        #   0x18 LB (Always 0x0F)
        #   start_time
        # }

        starttimetag = '\xA5\x11\x18\x0F'
        starttimetag += ticket_data.starttime

        # endtime{
        #   0xA5 LB (Always 0x11)
        #   0x18 LB (Always 0x0F)
        #   end_time
        # }
        endtimetag = '\xA6\x11\x18\x0F'
        endtimetag += ticket_data.endtime

        # renew_till{
        #   0xA5 LB (Always 0x11)
        #   0x18 LB (Always 0x0F)
        #   renew_till
        # }
        renewtag = '\xA7\x11\x18\x0F'
        renewtag += ticket_data.renew_till

        # This section represents the server realm (domain)
        # srealm{
        #   0xA8 LB
        #   0x1B LB
        #   server_realm (domain name of server)
        # }
        srealmtag = b''
        srealmtag += ticket_data.server_realm
        srealmtag = prepend(srealmtag,chr(len(srealmtag)))
        srealmtag = prepend(srealmtag,'\x1B')
        srealmtag = prepend(srealmtag,chr(len(srealmtag)))
        srealmtag = prepend(srealmtag,'\xA8')

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

        snametag = b''
        for s in ticket_data.server_components:
            snametag += '\x1B' + chr(len(s)) + s
        snametag = prepend(snametag, chr(len(snametag)))
        snametag = prepend(snametag, seqtag)
        snametag = prepend(snametag, chr(len(snametag)))
        snametag = prepend(snametag, '\xA1')
        snametag = prepend(snametag, '\xA0\x03\x02\x01' + chr(ticket_data.server_name_type))
        snametag = prepend(snametag, chr(len(snametag)))
        snametag = prepend(snametag, seqtag)
        snametag = prepend(snametag, chr(len(snametag)))
        snametag = prepend(snametag, '\xA9')

        # From this point on, we need to know the length of the rest of the file in bytes
        # The previous tags along with this one comprises the EncKrbCredPart
        krbcredlen = len(keytag) + len(prealmtag) + len(pnametag) + len(flags) + len(starttimetag) + len(endtimetag) + len(renewtag) + len(srealmtag) + len(snametag)

        # krbcredinfo{
        #   0x7D LT
        #   0x30 LT
        #   0xA0 LT
        #   0x30 LT
        #   0x30 LT
        # }
        krbcredinfo = ''
        krbcredinfo += struct.pack(">H", krbcredlen)
        krbcredinfo = prepend(krbcredinfo, seqtag + lentag)
        krbcredinfo = prepend(krbcredinfo, struct.pack(">H",krbcredlen + len(krbcredinfo)))
        krbcredinfo = prepend(krbcredinfo, seqtag + lentag)
        krbcredinfo = prepend(krbcredinfo, struct.pack(">H",krbcredlen + len(krbcredinfo)))
        krbcredinfo = prepend(krbcredinfo, '\xA0' + lentag)
        krbcredinfo = prepend(krbcredinfo, struct.pack(">H",krbcredlen + len(krbcredinfo)))
        krbcredinfo = prepend(krbcredinfo, seqtag + lentag)
        krbcredinfo = prepend(krbcredinfo, struct.pack(">H",krbcredlen + len(krbcredinfo)))
        krbcredinfo = prepend(krbcredinfo, '\x7D' + lentag)

        enckrbcredpart = krbcredinfo + keytag + prealmtag + pnametag + flags + starttimetag + endtimetag + renewtag + srealmtag + snametag

        # The encpart serves as a sort of header for the EncKrbCredPart
        # encpart{
        #   0xA0 0x03 0x02 0x01
        #   uint8 etype (Seems to always be 0 in my testing)
        #   0xA2 LT
        #   0x04 LT
        # }
        encpart = ''
        encpart += struct.pack(">H", len(enckrbcredpart))
        encpart = prepend(encpart, '\x04' + lentag)
        encpart = prepend(encpart, struct.pack(">H", len(encpart) + len(enckrbcredpart)))
        encpart = prepend(encpart, '\xA2' + lentag)
        encpart = prepend(encpart, '\xA0\x03\x02\x01' + chr(ticket_data.etype))

        newlength = len(encpart) + len(enckrbcredpart)

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
        ticketpart = ''
        ticketpart += struct.pack(">H",newlength)
        ticketpart = prepend(ticketpart, seqtag + lentag)
        ticketpart = prepend(ticketpart, struct.pack(">H",len(ticketpart) + newlength))
        ticketpart = prepend(ticketpart, '\xA3' + lentag)
        ticketpart = prepend(ticketpart, ticket_data.ticket)
        ticketpart = prepend(ticketpart, struct.pack(">H", len(ticket_data.ticket)))
        ticketpart = prepend(ticketpart, seqtag + lentag)
        ticketpart = prepend(ticketpart, struct.pack(">H", len(ticket_data.ticket) + 4))
        ticketpart = prepend(ticketpart, '\xA2' + lentag)
        
        newlength = newlength + len(ticketpart)

        # This is the header for the kerberos ticket, and the final section
        # header{
        #   0x76 LT
        #   0x30 LT
        #   0xA0 0x03 0x02 0x01
        #   uint8 pvno (Protocol Version, always 0x05)
        #   0xA1 0x03 0x02 0x01
        #   uint8 msg-type (Always 0x16 for krbcred)
        # }
        headertag = '\xA1\x03\x02\x01\x16'
        headertag = prepend(headertag, '\xA0\x03\x02\x01\x05')
        headertag = prepend(headertag, struct.pack(">H",len(headertag) + newlength))
        headertag = prepend(headertag, seqtag + lentag)
        headertag = prepend(headertag, struct.pack(">H",len(headertag) + newlength))
        headertag = prepend(headertag, '\x76' + lentag)

        # Write out everything to the file and we're done! 
        ticket.write(headertag)
        ticket.write(ticketpart)
        ticket.write(encpart)
        ticket.write(enckrbcredpart)