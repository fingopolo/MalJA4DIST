
from scapy.all import rdpcap, TCP, IP, Raw

# Cargar el archivo pcap

pcap_file_path = '/media/fingopolo/Maxtor/TFG/PREPRO_MalDIST/SESSIONS/Hancitor/Hancitor_CobaltStrike_2/session_0.pcap'

packets = rdpcap(pcap_file_path)



# Análisis inicial: contar paquetes, identificar protocolos

total_packets = len(packets)

tcp_packets = [pkt for pkt in packets if TCP in pkt]

http_requests = []

suspicious_packets = []



# Filtrar paquetes TCP con datos en bruto (posibles HTTP)

for pkt in tcp_packets:

    if Raw in pkt:
        payload = pkt[Raw].load
        try:
            # Detectar solicitudes HTTP
            if b"GET" in payload or b"POST" in payload or b"HTTP" in payload:
                http_requests.append(pkt)
                # Buscar posibles indicadores maliciosos en encabezados
                if b".exe" in payload or b"User-Agent" in payload:
                    suspicious_packets.append(pkt)
        except Exception:
            pass




print("total_packets", total_packets)
print("tcp_packets", len(tcp_packets))
print("http_requests", len(http_requests))
print("suspicious_packets", len(suspicious_packets))
