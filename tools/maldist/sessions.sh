#!/bin/bash


input_base_dir="Maxtor/"


output_base_dir="Maxtor/"


mkdir -p "$output_base_dir"


for input_pcap_file in "$input_base_dir"/*.pcap; do
    filename=$(basename -- "$input_pcap_file")
    filename_no_ext="${filename%.*}"
    
    output_dir="$output_base_dir/$filename_no_ext"
    mkdir -p "$output_dir"

    echo "Procesando archivo: $input_pcap_file"
    session_ids=$(tshark -r "$input_pcap_file" -T fields -e tcp.stream | sort -n | uniq)

    for session_id in $session_ids; do      
        session_file="$output_dir/session_$session_id.pcap"
        tshark -r "$input_pcap_file" -Y "tcp.stream==$session_id" -w "$session_file"
        echo "Guardando sesión en: $session_file"
    done
done