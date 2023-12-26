#!/usr/bin/python3


# Example code using scapy Python library 
# counts packets, TCP packets, UDP packets, and shows the time-of-arrival of HTTP requests 
# (c) 2023 R. P. Martin, GPL version 2

from scapy.all import *
import sys
import time
import math

# make sure to load the HTTP layer or your code wil silently fail
load_layer("http")

# name of the pcap file to load 
pcap_filename = "pcap3.pcap"

# example counters 
number_of_packets_total = 0  
number_of_tcp_packets = 0
number_of_udp_packets = 0
counter = 0
processed_file = rdpcap(pcap_filename)  # read in the pcap file 
sessions = processed_file.sessions()    #  get the list of sessions 
for session in sessions:                   
    for packet in sessions[session]:    # for each packet in each session
        number_of_packets_total = number_of_packets_total + 1  #increment total packet count 
        if packet.haslayer(TCP):        # check is the packet is a TCP packet
            number_of_tcp_packets = number_of_tcp_packets + 1   # count TCP packets 
            source_ip = packet[IP].src   # note that a packet is represented as a python hash table with keys corresponding to 
            dest_ip = packet[IP].dst     # layer field names and the values of the hash table as the packet field values
            source_port = packet[TCP].sport # get TCP ports
            dest_port = packet[TCP].dport
            if counter == 4:
                exit()
            if (packet.haslayer(HTTP)):
                counter += 1
                if HTTPRequest in packet:   
                    arrival_time = packet.time
                    print ("REQUEST: Got a TCP packet part of an HTTP request for server IP %s and server PORT %s" % (dest_ip, dest_port))
                if HTTPResponse in packet:
                    print ("RESPONSE: a TCP packet part of an HTTP response for server IP %s and server PORT %s" % (dest_ip, dest_port))
                # packet.show()

        else:
            if packet.haslayer(UDP):
                number_of_udp_packets = number_of_udp_packets + 1
                
print("Got %d packets total, %d TCP packets and %d UDP packets" % (number_of_packets_total, number_of_tcp_packets,number_of_udp_packets))

