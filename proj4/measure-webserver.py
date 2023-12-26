#!/usr/bin/python3


# Example code using scapy Python library 
# counts packets, TCP packets, UDP packets, and shows the time-of-arrival of HTTP requests 
# (c) 2023 R. P. Martin, GPL version 2

from scapy.all import *
import sys
import time
import math

def extraction(input_file, server_ip, server_port):

    # make sure to load the HTTP layer or your code wil silently fail
    load_layer("http")

    latencies = [] # will hold our computed latencies
    requests = {}
    processed_file = rdpcap(input_file)  # read in the pcap file 
    sessions = processed_file.sessions()    #  get the list of sessions 
    for session in sessions:                   
        for packet in sessions[session]:    # for each packet in each session
            if packet.haslayer(TCP):        # check is the packet is a TCP packet                
                if (packet.haslayer(HTTP)):
                    arrival_time = packet.time
                    source_ip = packet[IP].src # get IP addresses
                    dest_ip = packet[IP].dst

                    if HTTPRequest in packet:
                        if str(dest_ip) == server_ip:
                            requests[dest_ip] = arrival_time
                        else:
                            continue
                    
                    if HTTPResponse in packet:
                        if str(source_ip) == server_ip:
                            latencies.append(arrival_time - requests[source_ip])  
                        else:
                            continue
    get_latency_stats(latencies)

def get_latency_stats(latencies):
    latencies.sort()
    average_latency = float(math.fsum(latencies) / float(len(latencies)))
    formatted_average_latency = "{:1.5f}".format(average_latency)
    percentiles_needed = [25, 50, 75, 95, 99]
    percentiles = []
    for percentile in percentiles_needed:
        index = int(len(latencies) * percentile / 100)
        formatted_percentile = "{:1.5f}".format(latencies[index])
        percentiles.append(formatted_percentile)
    print("AVERAGE LATENCY: " + formatted_average_latency)
    print("PERCENTILES: ", str(percentiles[0]) + " " + str(percentiles[1]) + " " + str(percentiles[2]) + " " + str(percentiles[3]) + " " + str(percentiles[4]))
    compute_KL_divergence(latencies, average_latency)

def compute_KL_divergence(latencies, average_latency):
    measured_distribution, bucket_size = get_measured_distribution(latencies)
    modeled_distribution = get_modeled_distribution(latencies, average_latency, bucket_size)
    KL_divergence(measured_distribution, modeled_distribution)

def get_measured_distribution(latencies):
    measured_distribution = [0] * 10 # initialze to have 10 buckets
    # print(measured_distribution)
    bucket_size = float(latencies[-1] / 10) # get the bucket size

    for latency in latencies:
        index_after = 1
        for index in range(10):
            if (latency >= (index * bucket_size)) and (latency < (index_after * bucket_size)):
                measured_distribution[index] += 1
            else:
                index_after += 1
    for i in range(len(measured_distribution)):
        measured_distribution[i] = measured_distribution[i] / len(latencies)
    print(measured_distribution)

    return measured_distribution, bucket_size

def get_modeled_distribution(latencies, mean_response_time, bucket_size):
    latencies.sort()
    lambda_ = float(1 / mean_response_time)
    modeled_distribution = [0] * 10
    x1, x2 = 0, bucket_size
    for bucket in range(10):
        if bucket == 9:
            x2 = math.inf
        y1 = float(1.0 - math.exp(-lambda_ * x1))
        y2 = float(1.0 - math.exp(-lambda_ * x2))
        modeled_distribution[bucket] = y2 - y1
        x1, x2 = (x1 + bucket_size), (x2 + bucket_size)

    print(modeled_distribution)
    return modeled_distribution

def KL_divergence(distribution1, distribution2):
    
    if len(distribution1) != len(distribution2): # check that both distributions have the same number of buckets:
        raise ValueError("The input arrays must be equal size.")

    kl_sum = 0.0 # sum the components of the KL divergence from each bucket probability
    for i in range(len(distribution1)):

        if (distribution1[i] == 0.0) or (distribution2[i] == 0.0):
            continue
        kl_sum = kl_sum + (distribution1[i] * math.log2(distribution1[i]/distribution2[i]))
    
    formatted_kl_sum = "{:1.5f}".format(kl_sum)
    print("KL DIVERGENCE: " + formatted_kl_sum)

if __name__ == "__main__":
    input_file = sys.argv[1]
    server_ip = sys.argv[2]
    server_port = sys.argv[3]
    extraction(input_file, server_ip, server_port)