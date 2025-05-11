#!/bin/bash

input_dir="Maxtor/"

output_base_dir="Maxtor/"

mkdir -p "$output_base_dir"


for input_pcap_file in "$input_dir"/*.pcap; do
    file_name=$(basename "$input_pcap_file" .pcapng)
    
    output_dir="${output_base_dir}/${file_name}"
    
    mkdir -p "$output_dir"

    echo "Procesando ${input_pcap_file}..."
    ./tools/get-ja4.sh "$input_pcap_file" -a "MyApps" -t 0 -d "$output_dir" -w "utils/whois.txt"

    echo "Procesamiento de ${input_pcap_file} completado.\n"
done

echo "Todos los archivos han sido procesados."



