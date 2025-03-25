#!/bin/bash

# Número de sesiones a procesar
NUM_SESSIONS=17

# Ejecutar el script para cada sesión
for ((i=0; i<=NUM_SESSIONS; i++)); do
    echo "Procesando sesión $i"
    python3 preprocesing_oneF.py $i
done
