from scapy.all import rdpcap, TCP, UDP, IP, Raw
import numpy as np
from scipy.stats import skew
from collections import defaultdict
import pandas as pd
import os
import sys


# Cálculo de estadísticas
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
        sum(sizes) / (max(times) - min(times) + 1e-9) if len(times) > 1 else 0,  # Bytes/s
        len(packets) / (max(times) - min(times) + 1e-9) if len(times) > 1 else 0  # Packets/s
    ]
    return stats

# Extraer campos de protocolo
def extract_protocol_fields(packets, num_fields=32):
    protocol_matrix = np.zeros((num_fields, 10))  # Cambiar el tamaño si se necesitan más campos
    for i, packet in enumerate(packets[:num_fields]):
        if packet.haslayer(IP):
            protocol_matrix[i, 0] = packet[IP].version
            protocol_matrix[i, 1] = packet[IP].ihl
            protocol_matrix[i, 2] = packet[IP].tos
            protocol_matrix[i, 3] = packet[IP].len
            protocol_matrix[i, 4] = packet[IP].ttl
            protocol_matrix[i, 5] = packet[IP].proto
        if packet.haslayer(TCP):
            protocol_matrix[i, 6] = packet[TCP].sport
            protocol_matrix[i, 7] = packet[TCP].dport
            protocol_matrix[i, 8] = packet[TCP].flags.value
            protocol_matrix[i, 9] = packet[TCP].window
        # Añadir más campos según necesidad (UDP, ICMP, etc.)
    return protocol_matrix

# Procesar una sesión
def process_session(pcap_file):
    packets = rdpcap(pcap_file)
    
    
    # Calcular estadísticas 
    stats_matrix = np.zeros(14)  # Array 14
    stats_matrix = compute_stats(packets[:32])

    
    
    # Extraer campos de protocolo
    protocol_matrix = extract_protocol_fields(packets[:32])
    
    return stats_matrix, protocol_matrix


session_number = sys.argv[1]

input_dir = f"/media/fingopolo/Maxtor/TFG/PREPRO_MalDIST/SESSIONS/Emotet/Emotet_infection_Gootkit/session_{session_number}.pcap"  # Directorio con los archivos pcap de sesiones
output_csv = f"/media/fingopolo/Maxtor/TFG/PREPRO_MalDIST/FEATURES/Emotet/Emotet_infection_Gootkit_session_{session_number}.csv"


data = []

session_name = f"Emotet_infection_Gootkit_session{session_number}"  
print(f"Procesando: {input_dir} -> {session_name}")
result = process_session(input_dir)
if result:
    stats_matrix, protocol_matrix = result
    
    # Aplanar las matrices y concatenar las características
    stats_matrix = stats_matrix
    protocol_matrix = protocol_matrix.flatten()
    features = list(np.concatenate([stats_matrix, protocol_matrix]))
    
    
    features.insert(0, 2) # Añadir familia 0 benigno 1 Dridex 2 Emotet 3 Hancitor 4 Valak 5 Keylogger
    features.insert(0, 1)  # Añadir label 0 benigno 1 malware
    features.insert(0, session_name)  # Añadir nombre del archivo
    data.append(features)

# Guardar todas las características en un archivo CSV
columns = ["file_name", "label", "family"] + [f"stat_{i}" for i in range(14)] + [f"packet_{i}_protocol_{j}" for i in range(32) for j in range(10)]
df = pd.DataFrame(data, columns=columns)
df.to_csv(output_csv, index=False)

print(f"Características guardadas en: {output_csv}")