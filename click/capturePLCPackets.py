#!/usr/bin/env python3

import pcap
import dpkt
import binascii
import datetime
import pickle

class Packet(object):
    def __init__(self, data, timestamp):
        self.data = data
        self.timestamp = timestamp

SW_packets = []
PLC_packets = []

sniffer = pcap.pcap(name=None, promisc=True, immediate=True)
try:
    for timestamp, raw_buf in sniffer:
        output = {}

        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(raw_buf)
        output['eth'] = {'src': eth.src, 'dst': eth.dst, 'type':eth.type}

        # It this an IP packet?
        if not isinstance(eth.data, dpkt.ip.IP):
            #print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
            continue

        # Grab ip packet
        packet = eth.data

        # Pull out fragment information
        df = bool(packet.off & dpkt.ip.IP_DF)
        mf = bool(packet.off & dpkt.ip.IP_MF)
        offset = packet.off & dpkt.ip.IP_OFFMASK

        # Pulling out src, dst, length, fragment info, TTL, checksum and Protocol
        output['ip'] = {'src':packet.src, 'dst':packet.dst, 'p': packet.p,
                        'len':packet.len, 'ttl':packet.ttl,
                        'df':df, 'mf': mf, 'offset': offset,
                        'checksum': packet.sum}

        SW_ip = bytearray([10,0,0,39])
        PLC_ip = bytearray([10,0,0,30])
        interested = False
        if (packet.src == SW_ip and packet.dst == PLC_ip):
            interested = True
            print("SW->PLC")
            SW_packets.append(Packet(packet.data.data, int(timestamp)))
        elif (packet.src == PLC_ip and packet.dst == SW_ip):
            interested = True
            print("PLC->SW")
            PLC_packets.append(Packet(packet.data.data, int(timestamp)))

        if interested:
            print('Timestamp: ', str(datetime.datetime.fromtimestamp(timestamp)))
            print(int(timestamp), " seconds since epoch")
            print(binascii.hexlify(bytearray(packet.data.data)))

except KeyboardInterrupt:
    # Its important to use binary mode
    dbfile = open('capture.pkl', 'ab')

    db = {'SW': SW_packets,
          'PLC': PLC_packets}

    # source, destination
    pickle.dump(db, dbfile)
    dbfile.close()

