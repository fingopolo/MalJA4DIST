#!/bin/bash


input_dir="Maxtor/"


for folder in "$input_dir"/*/; do
    folder_name=$(basename "$folder")
    echo "Procesando carpeta: $folder_name"
    
    NUM_SESSIONS=$(ls -1q "$folder" | wc -l)
    echo "SESSIONS $NUM_SESSIONS"
    
    for file in "$folder"/*.pcap; do
        echo "Procesando archivo: $(basename "$file")"
        python3 preprocesing_oneF.py "$folder_name" "$(basename "$file")" "$mal_name"
    done

done
