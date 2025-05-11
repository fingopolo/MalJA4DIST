import pandas as pd


input_file = ""

column_to_modify = "family"  
new_value = 4  
df = pd.read_csv(input_file)
df[column_to_modify] = new_value


df.to_csv(input_file, index=False)
print(f"Columna '{column_to_modify}' modificada con éxito. Archivo guardado como '{input_file}'.")
