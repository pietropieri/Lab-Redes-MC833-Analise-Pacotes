from scapy.all import *
import os
import re

def analyze_pcap(file):
    packets = rdpcap(file) 
    ip_src = []
    ip_dst = []
    total_packets = 0
    packet_time = []
    total_data = 0
    first_time = None
    last_time = None

    # Filtrando apenas pacotes ICMP de tipo "Request"
    requests_packets = [packet for packet in packets if IP in packet and ICMP in packet and packet[ICMP].type == 8]
    
    for packet in echo_requests:
        if IP in packet and ICMP in packet:
            ip_src.append(packet[IP].src)
            ip_dst.append(packet[IP].dst)
            packet_time.append(packet.time)
            if first_time is None:
                first_time = packet.time
            last_time = packet.time
            total_data += len(packet)
            total_packets += 1

    # Calcula throughput
    duration = last_time - first_time if first_time and last_time else 1
    throughput = total_data / duration

    # Calcula intervalo entre pacotes
    packet_intervals = [j - i for i, j in zip(packet_time[:-1], packet_time[1:])]
    avg_interval = sum(packet_intervals) / len(packet_intervals) if packet_intervals else 0

    ip_src = list(set(ip_src))
    ip_dst = list(set(ip_dst))

    return ip_src, ip_dst, throughput, avg_interval, total_packets

# Funcao auxiliar para extrair nome dos hots dos arquivos .pcapng
def extract(file):
    match = re.search(r'H(\d)-H(\d)', file)
    h_src, h_dst = match.groups()
    res = f"Analysis for hosts {h_src} to {h_dst} ({file}):"
    return res


def main():
    files = ['H1-H3.pcapng', 'H2-H4.pcapng']
    for file in files:
        if os.path.exists(file):
            title = extract(file)
            print(title)
            ip_src, ip_dst, throughput, avg_interval, total_packets = analyze_pcap(file)
            print(f"IP de Origem: {ip_src}")
            print(f"IP Destino: {ip_dst}")
            print(f"Throughput: {throughput:.2f} bytes/segundo")
            print(f"Intervalo Médio de Pacotes: {avg_interval:.6f} segundos")
            print(f"Total de Pacotes: {total_packets}\n")


if __name__ == "__main__":
    main()
