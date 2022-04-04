from scapy.all import *

num_of_packets_to_sniff = 100
pcap = sniff(count=num_of_packets_to_sniff)

# rdpcap returns packet list
## packetlist object can be enumerated 
print(type(pcap))
print(len(pcap))
print(pcap)
pcap[0]

file = rdpcap("datasets/analisis_paquetes.pcap")

for pkt in pcap:
    file.append(pkt)

# rdpcap returns packet list
## packetlist object can be enumerated 
print(type(file))
print(len(file))
print(file)

file[0]
for i, pkt in enumerate(file):
    print(i)