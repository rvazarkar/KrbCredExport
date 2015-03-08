#!/usr/bin/env python

import krbcredstructs
import ccachestructs
import sys
import struct

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "Usage: {0} <input file> <output file>".format(sys.argv[0])
        sys.exit(0)

    with open(sys.argv[1], 'rb') as f:
        fileid, = struct.unpack(">B", f.read(1))
        if fileid == 0x5:
            print 'CCache File Found, Converting to kirbi'
            f.seek(0)
            header = ccachestructs.CCacheHeader()
            primary_principal = ccachestructs.Principal()
            credential = ccachestructs.Credential()

            header.parsefile(f)
            primary_principal.parsefile(f)
            credential.parsefile(f)

            KrbCred = krbcredstructs.KrbCredHeader()
            KrbCred.ticketpart.ticket = credential.ticket.data
            KrbCred.ticketpart.encpart.etype = credential.keyblock.etype
            krbcredinfo = KrbCred.ticketpart.encpart.krbcredinfo
            krbcredinfo.key.key = credential.keyblock.key
            krbcredinfo.key.keytype = credential.keyblock.keytype
            krbcredinfo.prealm.principal_realm = primary_principal.realm.data
            krbcredinfo.pname.principal_components = primary_principal.components
            krbcredinfo.pname.principal_name_type = primary_principal.name_type
            krbcredinfo.flags.ticket_flags = credential.tktFlags
            krbcredinfo.starttime.time = credential.times.starttime
            krbcredinfo.endtime.time = credential.times.endtime
            krbcredinfo.renew_till.time = credential.times.renew_till
            krbcredinfo.srealm.server_realm = credential.server.realm.data
            krbcredinfo.sname.server_components = credential.server.components
            krbcredinfo.sname.server_name_type = credential.server.name_type
            krbcredinfo.createkrbcrdinfo()

            with open(sys.argv[2], 'wb') as o:
                o.write(KrbCred.tostring())
            sys.exit(0)

        elif fileid == 0x76:
            print 'Ticket File Found, Converting to ccache'
            f.seek(0)
            KrbCred = krbcredstructs.KrbCredHeader()
            KrbCred.parsefile(f)

            header = ccachestructs.CCacheHeader()
            primary_principal = ccachestructs.Principal()
            credential = ccachestructs.Credential()

            header.version = 0x504
            header.header_length = 0xC
            header.header.deltatime.time_offset = 4294967295
            header.header.deltatime.usec_offset = 0
            header.header.tag = 0x01
            header.header.taglen = 0x08
            KrbCredInfo = KrbCred.ticketpart.encpart.krbcredinfo

            primary_principal.name_type = KrbCredInfo.pname.principal_name_type
            primary_principal.components = KrbCredInfo.pname.principal_components
            primary_principal.num_components = len(primary_principal.components)
            primary_principal.realm.data = KrbCredInfo.prealm.principal_realm
            primary_principal.realm.length = len(primary_principal.realm.data)

            credential.client.name_type = KrbCredInfo.pname.principal_name_type
            credential.client.components = KrbCredInfo.pname.principal_components
            credential.client.num_components = len(credential.client.components)
            credential.client.realm.data = KrbCredInfo.prealm.principal_realm
            credential.client.realm.length = len(credential.client.realm.data)

            credential.server.name_type = KrbCredInfo.sname.server_name_type
            credential.server.components = KrbCredInfo.sname.server_components
            credential.server.num_components = len(credential.server.components)
            credential.server.realm.data = KrbCredInfo.srealm.server_realm
            credential.server.realm.length = len(credential.server.realm.data)

            credential.keyblock.etype = KrbCred.ticketpart.encpart.etype
            credential.keyblock.key = KrbCredInfo.key.key
            credential.keyblock.keylen = len(credential.keyblock.key)
            credential.keyblock.keytype = KrbCredInfo.key.keytype

            credential.times.authtime = KrbCredInfo.starttime.time
            credential.times.starttime = KrbCredInfo.starttime.time
            credential.times.endtime = KrbCredInfo.endtime.time
            credential.times.renew_till = KrbCredInfo.renew_till.time

            credential.is_skey = 0

            credential.tktFlags = KrbCredInfo.flags.ticket_flags

            credential.num_address = 0
            credential.address = []

            credential.num_authdata = 0
            credential.authdata = []

            credential.ticket.data = KrbCred.ticketpart.ticket
            credential.ticket.length = len(credential.ticket.data)

            credential.secondticket.length = 0
            credential.secondticket.data = ''

            with open(sys.argv[2], 'wb') as o:
                o.write(header.tostring())
                o.write(primary_principal.tostring())
                o.write(credential.tostring())
                sys.exit(0)
        else:
            print 'Unknown File Type'
            sys.exit(0)
