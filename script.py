# from scapy.all import *
from scapy.all import *
import os

def analyze_pcap(file):
    packets = rdpcap(file)
    ip_src = []
    ip_dst = []
    total_packets = len(packets)
    packet_intervals = []
    total_data = 0
    first_time = None
    last_time = None

    for packet in packets:
        if IP in packet:
            ip_src.append(packet[IP].src)
            ip_dst.append(packet[IP].dst)
            if first_time is None:
                first_time = packet.time
            last_time = packet.time
            total_data += len(packet)

    # Calculating throughput (bytes per second)
    duration = last_time - first_time if first_time and last_time else 1
    throughput = total_data / duration

    # Calculating average interval between packets
    packet_intervals = [j - i for i, j in zip(packet_time[:-1], packet_time[1:])]
    avg_interval = sum(packet_intervals) / len(packet_intervals) if packet_intervals else 0

    ip_src = list(set(ip_src))
    ip_dst = list(set(ip_dst))

    return ip_src, ip_dst, throughput, avg_interval, total_packets

def main():
    files = ['h1_h3.pcap', 'h2_h4.pcap']  # replace with your PCAP filenames
    for file in files:
        if os.path.exists(file):
            ip_src, ip_dst, throughput, avg_interval, total_packets = analyze_pcap(file)
            print(f"Analysis for {file}:")
            print(f"Source IPs: {ip_src}")
            print(f"Destination IPs: {ip_dst}")
            print(f"Throughput: {throughput:.2f} bytes/second")
            print(f"Average Packet Interval: {avg_interval:.6f} seconds")
            print(f"Total Packets: {total_packets}\n")
        else:
            print(f"File {file} does not exist")

if __name__ == "__main__":
    main()
