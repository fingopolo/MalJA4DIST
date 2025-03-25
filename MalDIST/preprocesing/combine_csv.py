import os
import pandas as pd

# Directorio donde se encuentran los archivos CSV
input_dir = "/media/fingopolo/Maxtor/TFG/PREPRO_MalDIST/FEATURES/ALL"
output_csv = "/media/fingopolo/Maxtor/TFG/PREPRO_MalDIST/FEATURES/ALL/MalDist_Dataset.csv"

# Crear una lista para almacenar los DataFrames
dataframes = []

# Iterar sobre todos los archivos CSV en el directorio
for csv_file in os.listdir(input_dir):
    if csv_file.endswith(".csv"):  # Verificar que el archivo tenga extensión .csv
        full_path = os.path.join(input_dir, csv_file)
        print(f"Procesando: {csv_file}")
        # Cargar el CSV y agregarlo a la lista
        df = pd.read_csv(full_path)
        dataframes.append(df)

# Combinar todos los DataFrames en uno solo
combined_df = pd.concat(dataframes, ignore_index=True)

# Guardar el DataFrame combinado en un archivo CSV
combined_df.to_csv(output_csv, index=False)

print(f"Archivos combinados guardados en: {output_csv}")
