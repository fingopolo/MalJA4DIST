import pandas as pd
import argparse


parser = argparse.ArgumentParser(description="Une huellas JA4S y JA4X de dos archivos csv")
parser.add_argument("ja4", help="Archivo JA4 fingerprint")
#parser.add_argument("ja4x", help="Archivo JA4X fingerprint")
parser.add_argument("ja4ts", help="Archivo JA4TS fingerprint")
parser.add_argument("-o", "--output", help="Archivo CSV de salida", default="output.csv")
args = parser.parse_args()


df_ja4s_ja4 = pd.read_csv(args.ja4, sep=";")
df_ja4x = pd.read_csv(args.ja4x, sep=";")
df_ja4ts = pd.read_csv(args.ja4ts, sep=";")


# Realizar el full join (outer join) en las columnas especificadas
full_join = pd.merge(
    df_ja4s_ja4,
    df_ja4x,
    on=['SrcIP', 'DstIP', 'SrcPort', 'DstPort'],
    how='outer',
    suffixes=('_ja4s_ja4', '_ja4x')
)

full_join = pd.merge(
    df_ja4s_ja4,
    df_ja4ts,
    on=["SrcIP", "DstIP", "SrcPort", "DstPort"],
    how="outer"
)


full_join.to_csv(args.output, index=False, sep=";")

print(f"Full join completado. Resultado guardado en {args.output}")