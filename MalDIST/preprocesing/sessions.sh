#!/bin/bash

# Archivo pcap de entrada
input_pcap_file="/media/fingopolo/Maxtor/TFG/Datasets/Malware-Emotet/2018-12-20-Emotet-infection-with-Gootkit.pcap"

# Directorio donde se guardarán las sesiones
output_dir="/media/fingopolo/Maxtor/TFG/PREPRO_MalDIST/SESSIONS/Emotet/Emotet_infection_Gootkit"

# Crear el directorio de salida si no existe
mkdir -p "$output_dir"

# Extraer los números de las sesiones (tcp.stream) únicas
session_ids=$(tshark -r "$input_pcap_file" -T fields -e tcp.stream | sort -n | uniq)

# Procesar cada sesión
for session_id in $session_ids; do
    # Crear un nombre de archivo para la sesión
    session_file="$output_dir/session_$session_id.pcap"

    # Filtrar los paquetes de la sesión específica y guardarlos en un archivo pcap
    tshark -r "$input_pcap_file" -Y "tcp.stream==$session_id" -w "$session_file"

    echo "Guardando sesión en: $session_file"
done
