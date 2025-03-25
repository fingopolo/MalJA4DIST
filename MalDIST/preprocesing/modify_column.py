import pandas as pd

# Ruta del archivo CSV
input_file = "/media/fingopolo/Maxtor/TFG/PREPRO_MalDIST/FEATURES/Hancitor/Hancitor_CobaltStrike_2.csv"


# Nombre de la columna a modificar y el valor nuevo (o lógica de transformación)
column_to_modify = "label"  # Cambia esto por el nombre de la columna
new_value = 1  # Cambia esto por el valor que quieres asignar

# Leer el archivo CSV
df = pd.read_csv(input_file)

# Modificar los valores de la columna
df[column_to_modify] = new_value

# Guardar los cambios en un nuevo archivo CSV
df.to_csv(input_file, index=False)

print(f"Columna '{column_to_modify}' modificada con éxito. Archivo guardado como '{input_file}'.")
