import os
import pandas as pd
import sys


input_dir = ""
output_csv = ""

dataframes = []

for csv_file in os.listdir(input_dir):
    if csv_file.endswith(".csv"):  
        full_path = os.path.join(input_dir, csv_file)
        print(f"Procesando: {csv_file}")
    
        df = pd.read_csv(full_path)
        dataframes.append(df)


combined_df = pd.concat(dataframes, ignore_index=True)


combined_df.to_csv(output_csv, index=False)

print(f"Archivos combinados guardados en: {output_csv}")
