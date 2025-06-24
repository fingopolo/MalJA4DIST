import subprocess
import csv

def parse_tcp_options_raw(hex_str):
    """Parsea la cadena hexadecimal cruda de tcp.options y extrae los tipos en orden"""
    types = []
    i = 0
    while i < len(hex_str):
        kind = int(hex_str[i:i+2], 16)
        types.append(str(kind))

        if kind in [0, 1]:  # EOL o NOP → solo 1 byte
            i += 2
        else:
            if i + 4 > len(hex_str):
                print("MAL")
                break  # Malformado
            length = int(hex_str[i+2:i+4], 16)
            i += length * 2
    return "-".join(types)

def extract_ja4ts_tshark(pcap_file, output_csv):
    # Campos necesarios
    fields = [
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.window_size_value",      # ja4_a
        "tcp.options",                # ja4_b (orden de opciones)
        "tcp.options.mss_val",        # ja4_c
        "tcp.options.wscale.shift"          # ja4_d
    ]

    # Comando tshark para SYN-ACK
    cmd = [
        "tshark", "-r", pcap_file,
        "-Y", "tcp.flags == 0x12",
        "-T", "fields"
    ]

    for field in fields:
        cmd.extend(["-e", field])

    # Separador para columnas
    cmd.extend(["-E", "separator=,", "-E", "quote=d", "-E", "occurrence=f"])

    # Ejecutar tshark
    result = subprocess.run(cmd, capture_output=True, text=True)
    lines = result.stdout.strip().split("\n")

    with open(output_csv, "w", newline="") as f:
        writer = csv.writer(f, delimiter=";")
        writer.writerow(["SrcIP", "DstIP", "SrcPort", "DstPort", "ja4ts"])  # cabecera

        for line in lines:
            parts = [p.strip('"') for p in line.split(",")]
            if len(parts) != len(fields):
                continue  # saltar líneas incompletas

            src_ip, dst_ip, src_port, dst_port, ja4_a, options_raw, mss, wscale = parts

            ja4_b = parse_tcp_options_raw(hex_str=options_raw)
            

            ja4_a = ja4_a or "0"
            mss = mss or "0"
            wscale = wscale or "0"

            ja4ts = f"{ja4_a}-{ja4_b}-{mss}-{wscale}"

            writer.writerow([dst_ip, src_ip, dst_port, src_port, ja4ts])

    print(f"[✓] CSV generado en '{output_csv}'")


# Ejemplo de uso
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Extraer JA4TS desde SYN-ACK en un PCAP")
    parser.add_argument("pcap", help="Archivo PCAP de entrada")
    parser.add_argument("-o", "--output", help="Archivo CSV de salida", default="ja4ts_output.csv")
    args = parser.parse_args()

    extract_ja4ts_tshark(args.pcap, args.output)
