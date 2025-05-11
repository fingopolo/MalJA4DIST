from scapy.all import rdpcap, TCP, UDP, IP, Raw
import numpy as np
from scipy.stats import skew
from collections import defaultdict
import pandas as pd
import os
import sys

def identify_src_dst_ips(packets):
    src_ip, dst_ip = None, None
    
    for packet in packets:
        if not packet.haslayer(TCP):
            continue  
            
        if packet[TCP].flags & 0x02 and not packet[TCP].flags & 0x10: 
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            break
            
        
        elif packet[TCP].flags & 0x12:  
            src_ip = packet[IP].dst  
            dst_ip = packet[IP].src 
            break
    
    
    if src_ip is None:
        print("NO HAY SYN y ACK")
        for packet in packets:
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                break
    
    return src_ip, dst_ip


def compute_stats(packets):
    sizes = [float(len(p)) for p in packets]
    times = [float(p.time) for p in packets]
    intervals = np.array(np.diff(times)) if len(times) > 1 else np.array([])

    
    stats = [
        np.min(sizes) if sizes else 0,
        np.max(sizes) if sizes else 0,
        np.mean(sizes) if sizes else 0,
        np.std(sizes) if sizes else 0,
        skew(sizes) if len(sizes) > 1 else 0,
        np.min(intervals) if intervals.size else 0,
        np.max(intervals) if intervals.size else 0,
        np.mean(intervals) if intervals.size else 0,
        np.std(intervals) if intervals.size else 0,
        skew(intervals) if len(intervals) > 1 else 0,
        sum(sizes),
        len(packets),
        sum(sizes) / (max(times) - min(times) + 1e-9) if len(times) > 1 else 0,  
        len(packets) / (max(times) - min(times) + 1e-9) if len(times) > 1 else 0  
    ]
    return stats


def extract_protocol_fields(packets, num_packets=32):
    protocol_matrix = np.zeros((num_packets, 4)) 
    
    if not packets:
        return protocol_matrix
    
    src_ip, dst_ip = identify_src_dst_ips(packets[:32])
    
    
    prev_time = packets[0].time if hasattr(packets[0], 'time') else 0.0
    
    for i, packet in enumerate(packets[:num_packets]):
        if i > 0:
            delta_time = packet.time - prev_time
            prev_time = packet.time
        else:
            delta_time = 0.0
        
        
        direction = 0
        if hasattr(packet, 'src') and hasattr(packet, 'dst'):
            if packet.src == dst_ip and packet.dst == src_ip: 
                direction = 1
        
        
        pkt_size = len(packet)
        
        
        pkt_iat = delta_time
        
        tcp_window = 0
        if TCP in packet:
            tcp_window = packet[TCP].window
        
        protocol_matrix[i] = [direction, pkt_size, pkt_iat, tcp_window]
    
    return protocol_matrix


def process_session(pcap_file):
    packets = rdpcap(pcap_file)
    
    groups = {
        "bidirectional" : [],
        "srcdst" : [],
        "dstsrc" : [],
        "handshake" : [],
        "datatransfer" : []
    }
    if not packets:
        return None, None  
    
    
    src_ip, dst_ip = identify_src_dst_ips(packets[:32])

    
    for packet in packets[:32]:
        groups['bidirectional'].append(packet)

        if src_ip and dst_ip:
            if packet['IP'].src == src_ip and packet['IP'].dst == dst_ip:
                groups['srcdst'].append(packet)
            elif packet['IP'].src == dst_ip and packet['IP'].dst == src_ip:
                groups['dstsrc'].append(packet)

        if TCP in packet:
            if packet[TCP].flags & 2:  # SYN flag
                groups['handshake'].append(packet)
            else:
                groups['datatransfer'].append(packet)
        else:
            groups['datatransfer'].append(packet)
        
    
    
    stats_matrix = np.zeros((5, 14))  
    for i, group in enumerate(groups.values()):
        stats_matrix[i, :] = compute_stats(group)

    
    
    protocol_matrix = extract_protocol_fields(packets[:32])
    
    return stats_matrix, protocol_matrix


file_name = sys.argv[1]
session_number = sys.argv[2]
mal_name = sys.argv[3]
session_number = session_number.split('.pcap')[0]

input_dir = f"/media/fingopolo/Maxtor/TFG/MalDIST/DATASET1/GROUPS/SESSIONS/VALAK/{mal_name}/{file_name}/{session_number}.pcap"  # Directorio con los archivos pcap de sesiones
output_csv = f"/media/fingopolo/Maxtor/TFG/MalDIST/DATASET1/GROUPS/FEATURES/VALAK/{mal_name}_{file_name}_{session_number}.csv"


data = []

session_name = f"{file_name}_{session_number}"  
print(f"Procesando: {input_dir} -> {session_name}")
result = process_session(input_dir)
if result:
    stats_matrix, protocol_matrix = result
    
    stats_matrix = stats_matrix.flatten()
    protocol_matrix = protocol_matrix.flatten()
    features = list(np.concatenate([stats_matrix, protocol_matrix]))
    
    
    features.insert(0, 2) # Añadir familia 0 benigno 1 Dridex 2 Emotet 3 Hancitor 4 Valak 5 Keylogger
    features.insert(0, 1)  # Añadir label 0 benigno 1 malware
    features.insert(0, session_name)  
    data.append(features)

columns =   ["file_name", "label", "family"] + \
            [f"bidirectional_{field}" for field in ["min_size","max_size","mean_size", "std_size", "skew_size", "min_time","max_time","mean_time", "std_time", "skew_time","tot_size", "num_packets", "byte/s", "packet/s"]] + \
            [f"src2dst_{field}" for field in ["min_size","max_size","mean_size", "std_size", "skew_size", "min_time","max_time","mean_time", "std_time", "skew_time","tot_size", "num_packets", "byte/s", "packet/s"]] + \
            [f"dst2src_{field}" for field in ["min_size","max_size","mean_size", "std_size", "skew_size", "min_time","max_time","mean_time", "std_time", "skew_time","tot_size", "num_packets", "byte/s", "packet/s"]] + \
            [f"handshake_{field}" for field in ["min_size","max_size","mean_size", "std_size", "skew_size", "min_time","max_time","mean_time", "std_time", "skew_time","tot_size", "num_packets", "byte/s", "packet/s"]] + \
            [f"datatransfer_{field}" for field in ["min_size","max_size","mean_size", "std_size", "skew_size", "min_time","max_time","mean_time", "std_time", "skew_time","tot_size", "num_packets", "byte/s", "packet/s"]] + \
            [f"packet_{i+1}_{field}" for i in range(32) for field in ["direction", "size", "iat", "tcp_window"]]
df = pd.DataFrame(data, columns=columns)
df.to_csv(output_csv, index=False)

print(f"Características guardadas en: {output_csv}")