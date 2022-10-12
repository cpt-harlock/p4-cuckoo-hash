from scapy.all import *
import os
import sys

#capture = input("Enter file path of pcap file: " )

capture = sys.argv[1]  
pcap = rdpcap(capture)

s = set()
try:
    os.remove('filtered.pcap')
except :
    print("no file to remove")

def write(pkt):
    wrpcap('filtered.pcap', pkt, append=True, linktype=101 )  #appends packet to output file

for pkt in pcap:
    ip_hdr = pkt.getlayer(IP)
    if ip_hdr.src not in s:  #checks for UDP layer and sport 137
        write(pkt)  #sends the packet to be written if it meets criteria
        s.add(ip_hdr.src)

print("uniq keys: ", len(s))
