from scapy.all import rdpcap, TCP, UDP, IP, Raw
import numpy as np
from scipy.stats import skew
from collections import defaultdict
import pandas as pd
import os

# Clasificación de paquetes en los 5 grupos
def classify_packet(packet, src_ip, dst_ip):
    if packet.haslayer('IP'):
        pkt_src = packet['IP'].src
        pkt_dst = packet['IP'].dst
        if pkt_src == src_ip and pkt_dst == dst_ip:
            return 'source-destination'
        elif pkt_src == dst_ip and pkt_dst == src_ip:
            return 'destination-source'
        else:
            return 'bidirectional'
    elif packet.haslayer('TCP'):
        if 'S' in packet['TCP'].flags:  # TCP SYN
            return 'handshake'
        elif 'A' in packet['TCP'].flags:  # TCP ACK
            return 'data-transfer'
    return 'other'

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
    groups = {
        'bidirectional': [], 
        'source-destination': [],
        'destination-source': [], 
        'handshake': [], 
        'data-transfer': []
    }
    
    # Asumimos que la IP origen/destino son del primer paquete
    if packets and packets[0].haslayer('IP'):
        src_ip = packets[0]['IP'].src
        dst_ip = packets[0]['IP'].dst
    else:
        print(f"No se encontró capa IP en el archivo {pcap_file}")
        return None
    
    for packet in packets[:32]:  # Procesar los primeros 32 paquetes
        group = classify_packet(packet, src_ip, dst_ip)
        if group in groups:
            groups[group].append(packet)
    
    # Calcular estadísticas para cada grupo
    stats_matrix = np.zeros((5, 14))  # Matriz 5x14
    for i, group in enumerate(groups.values()):
        stats_matrix[i, :] = compute_stats(group)
    
    # Extraer los primeros 784 bytes del payload
    payload = b''.join(bytes(packet[Raw])[:784] for packet in packets if Raw in packet)
    payload = payload.ljust(784, b'\x00')  # Rellenar con ceros si es menor a 784 bytes
    
    # Extraer campos de protocolo
    protocol_matrix = extract_protocol_fields(packets[:32])
    
    return stats_matrix, payload, protocol_matrix




# Directorios de entrada y salida
input_dir = "/media/fingopolo/Maxtor/TFG/PREPRO_MalDIST/SESSIONS/VPN-PCAPs-02/voipbuster1b"
output_csv = "/media/fingopolo/Maxtor/TFG/PREPRO_MalDIST/FEATURES/VPN-PCAPs-02/voipbuster1b.csv"

all_data = []

for idx, pcap_file in enumerate(os.listdir(input_dir)):
    full_path = os.path.join(input_dir, pcap_file)
    session_name = f"voipbuster1b_session{idx}"  
    print(f"Procesando: {pcap_file} -> {session_name}")
    
    result = process_session(full_path)  # Llama a tu función de procesamiento
    if result:
        stats_matrix, payload, protocol_matrix = result
        
        # Aplanar las matrices y concatenar las características
        stats_matrix = stats_matrix.flatten()
        protocol_matrix = protocol_matrix.flatten()
        features = np.concatenate([stats_matrix, protocol_matrix, [payload.hex()]])
        
        
        all_data.append(np.insert(features, 0, [session_name, 0]))  # Nombre al inicio, etiqueta al final
        

# Crear columnas dinámicas
columns = ["file_name"] + ["label"] + [f"feature_{i}" for i in range(len(all_data[0]) - 2)] 

# Guardar en un archivo CSV
df = pd.DataFrame(all_data, columns=columns)
df.to_csv(output_csv, index=False)

print(f"Características guardadas en: {output_csv}")