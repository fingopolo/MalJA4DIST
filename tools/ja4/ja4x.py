import os
import sys
import json
import csv
from hashlib import sha256
import argparse
from subprocess import PIPE, Popen
from datetime import datetime
import signal


SAMPLE_COUNT = 200
raw_fingerprint = False
original_rendering = False
output_types = ['ja4x']  
debug = False
mode = "default"
fp_out = None
jsons = []
conn_cache = {}
http_cache = {}
quic_cache = {}
TCP_FLAGS = { 'SYN': 0x0002, 'ACK': 0x0010, 'FIN': 0x0001 }


keymap = {
    'frame': {'frno': 'number', 'protos': 'protocols', 'timestamp': 'time_epoch'},
    'ip': {'src': 'src', 'dst': 'dst', 'ttl': 'ttl'},
    'ipv6': {'src': 'src', 'dst': 'dst', 'ttl': 'hlim'},
    'tcp': {'flags': 'flags', 'ack': 'ack', 'seq': 'seq', 'fin': 'flags_fin', 'stream': 'stream', 'srcport': 'srcport', 'dstport': 'dstport', 'len': 'len', 'flags_ack': 'flags_ack'},
    'udp': {'stream': 'stream', 'srcport': 'srcport', 'dstport': 'dstport'},
    'quic': {'packet_type': 'long_packet_type'},
    'tls': {'version': 'handshake_version', 'type': 'handshake_type', 'extensions': 'handshake_extension_type', 'ciphers': 'handshake_ciphersuite', 'domain': 'handshake_extensions_server_name', 'supported_versions': 'handshake_extensions_supported_version', 'alpn': 'handshake_extensions_alps_alpn_str', 'alpn_list': 'handshake_extensions_alpn_str', 'sig_alg_lengths': 'handshake_sig_hash_alg_len', 'signature_algorithms': 'handshake_sig_hash_alg'},
    'x509af': {'cert_extensions': 'extension_id', 'extension_lengths': 'extensions', 'subject_sequence': 'rdnSequence'},
    'http': {'method': 'request_method', 'headers': 'request_line', 'cookies': 'cookie', 'lang': 'accept_language'},
    'http2': {'method': 'headers_method', 'headers': 'header_name', 'lang': 'headers_accept_language', 'cookies': 'headers_set_cookie', 'cookies': 'headers_cookie'},
    'ssh': {'ssh_protocol': 'protocol', 'hassh': 'kex_hassh', 'hassh_server': 'kex_hasshserver', 'direction': 'direction', 'algo_client': 'encryption_algorithms_client_to_server', 'algo_server': 'encryption_algorithms_server_to_client'}
}




def sha_encode(values):
    if isinstance(values, list):
        return sha256(','.join(values).encode('utf8')).hexdigest()[:12]
    else:
        return sha256(values.encode('utf8')).hexdigest()[:12]

def get_cache(x):
    if x['hl'] in [ 'http', 'http2']:
        return http_cache
    elif x['hl'] == 'quic':
        return quic_cache
    else:
        return conn_cache

def cache_update(x, field, value, debug_stream=-1):
    cache = get_cache(x)
    stream = int(x['stream'])
    update = False

    if field == 'stream' and stream not in cache:
        cache[stream] = { 'stream': stream}
        return

    # Do not update main tuple fields if they are already in
    if field in [ 'stream', 'src', 'dst', 'srcport', 'dstport', 'A', 'B', 'JA4S', 'D', 'server_extensions', 'count', 'stats'] and field in cache[stream]:
        return

    # update protos only if we have extra information
    if field == 'protos':
        if field in cache[stream] and len(value) <= len(cache[stream][field]):
            return

    # special requirement for ja4c when the C timestamp needs to be the
    # the last before D
    if field == 'C' and 'D' in cache[stream]:
        return

    if stream in cache:
        cache[stream][field] = value
        update = True
    return update

def scan_tls(layer):
    if not layer:
        return None

    if not isinstance(layer, list):
        if 'tls_tls_handshake_type' in layer:
            return layer
    else:
        for l in layer:
            if 'tls_tls_handshake_type' in l:
                return l

def layer_update(x, pkt, layer):
    #print(f"Procesando capa: {layer}")  # Depuración
    l = None
    x['hl'] = layer
    if layer == 'quic':
        quic = pkt['layers'].pop('quic', None)
        if quic:
            if isinstance(quic, list):
                quic = quic[0]
            [x.update({key: quic[f'{layer}_{layer}_{item}']}) for key, item in keymap[layer].items() if f'{layer}_{layer}_{item}' in quic]
            l = quic['tls'] if 'tls' in quic.keys() else None
            layer = 'tls'
    else:
        l = pkt['layers'].pop(layer, None) if layer != 'x509af' else pkt['layers'].pop('tls', None)
        #print(f"Datos de la capa {layer}: {l}")  # Depuración

    if layer == 'tls':
        l = scan_tls(l)
    else:
        l = l[0] if isinstance(l, list) else l

    if l:
        #print(f"Actualizando datos de la capa {layer}")  # Depuración
        [x.update({key: l[f'{layer}_{layer}_{item}']}) for key, item in keymap[layer].items() if f'{layer}_{layer}_{item}' in l]

    if layer == 'x509af' and l:
        [x.update({key: l[f'tls_tls_{item}']}) for key, item in keymap['tls'].items() if f'tls_tls_{item}' in l]
        x.update({'issuer_sequence': l['x509if_x509if_rdnSequence']}) if 'x509if_x509if_rdnSequence' in l else None
        if 'x509if_x509if_id' in l:
            x.update({'rdn_oids': l['x509if_x509if_id']})
        if 'x509if_x509if_oid' in l:
            x.update({'rdn_oids': l['x509if_x509if_oid']})
        x.update({'printable_certs': l['x509sat_x509sat_printableString']}) if 'x509sat_x509sat_printableString' in l else None

def encode_variable_length_quantity(v: int) -> list:
    m = 0x00
    output = []
    while v >= 0x80:
        output.insert(0, (v & 0x7F) | m)
        v = v >> 7
        m = 0x80
    output.insert(0, v | m)
    return output

def oid_to_hex(oid: str) -> str:
    a = [int(x) for x in oid.split(".")]
    oid = [a[0] * 40 + a[1]]
    for n in a[2:]:
        oid.extend(encode_variable_length_quantity(n))
    oid.insert(0, len(oid))
    oid.insert(0, 0x06)
    return "".join("{:02x}".format(num) for num in oid)[4:]

def get_CN_ON(certs, seq):
    CN = None
    ON = None
    for i in seq:
        popped = certs.pop(0)
        if i == '55040a':
            ON = popped
        if i == '550403':
            CN = popped
    if CN and ON:
        return f"CN={CN}, ON={ON}"
    else:
        raise Exception('no CN ON found')

def remove_oids(seq, oids):
    for oid in oids:
        seq.remove(oid) if oid in seq else None

def issuers_subjects(x):
    for issuer_len, subject_len in zip(x['issuer_sequence'], x['subject_sequence']):
        # we have one issuer and subject sequence for each certificate
        issuers = []
        subjects = []
        for i in range(0, int(issuer_len)):
            issuer = x['rdn_oids'].pop(0)
            issuers.append(oid_to_hex(issuer))
        for i in range(0, int(subject_len)):
            subject = x['rdn_oids'].pop(0)
            subjects.append(oid_to_hex(subject))

        yield issuers, subjects, sha_encode(issuers), sha_encode(subjects)


# Función principal para JA4X
def to_ja4x(x, debug_stream=-1):
    if 'extension_lengths' not in x:
        print("No se encontró 'extension_lengths'. Retornando.")  # Depuración
        return

    x['issuers'] = []
    x['subjects'] = []
    x['issuer_hashes'] = []
    x['subject_hashes'] = []
    x['ja4x_list'] = []  # Lista para almacenar todas las huellas JA4X
    x['issuer_list'] = []  # Lista para almacenar todos los Issuers
    x['subject_list'] = []  # Lista para almacenar todos los Subjects

    for issuers, subjects, i_hash, s_hash in issuers_subjects(x):
        x['issuers'].append(issuers)
        x['subjects'].append(subjects)
        x['issuer_hashes'].append(i_hash)
        x['subject_hashes'].append(s_hash)
    

    if 'printable_certs' in x:
        certs = str(x['printable_certs'])
        issuers = str(x['issuers'])
        subjects = str(x['subjects'])
        idx = 1
        for _i, _s in zip(issuers, subjects):
            remove_oids(_i, ['550406', '55040b'])
            remove_oids(_s, ['550406', '55040b'])

            try:
                cn_on = get_CN_ON(certs, _i)
                x[f'JA4X.{idx}._Issuer'] = cn_on
                x['issuer_list'].append(cn_on)  # Agregar Issuer a la lista
                cache_update(x, f'JA4X.{idx}._Issuer', x[f'JA4X.{idx}._Issuer'], debug_stream)
            except Exception as e:
                pass

            try:
                cn_on = get_CN_ON(certs, _s)
                x[f'JA4X.{idx}._Subject'] = cn_on
                x['subject_list'].append(cn_on)  # Agregar Subject a la lista
                cache_update(x, f'JA4X.{idx}._Subject', x[f'JA4X.{idx}._Subject'], debug_stream)
            except Exception as e:
                pass

            idx += 1

    for idx, i in enumerate(x['extension_lengths']):
        if idx >= len(x["issuer_hashes"]) or idx >= len(x["subject_hashes"]):
            continue  
        i = int(i)
        header_len = '{:02d}'.format(i)
        exts = x['cert_extensions'][:i] if isinstance(x['cert_extensions'], list) else [x['cert_extensions']]
        if isinstance(x['cert_extensions'], list):
            del x['cert_extensions'][:i]
        hex_strings = [oid_to_hex(ext) for ext in exts]

        ja4x = f'{x["issuer_hashes"][idx]}_{x["subject_hashes"][idx]}_' + sha256(",".join(hex_strings).encode('utf8')).hexdigest()[:12]
        x[f'JA4X.{idx+1}'] = ja4x
        x['ja4x_list'].append(ja4x)  
        cache_update(x, f'JA4X.{idx+1}', x[f'JA4X.{idx+1}'], debug_stream)
    return x

def save_to_csv(data, filename):
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file, delimiter=';')
        # Encabezados del CSV
        writer.writerow(['SrcIP', 'DstIP', 'SrcPort', 'DstPort', 'JA4X', 'Issuer', 'Subject'])
        
        for entry in data:
            # Unir todas las huellas JA4X en una sola cadena separada por comas
            ja4x_str = ', '.join(entry.get('ja4x_list', []))
            # Unir todos los Issuers en una sola cadena separada por comas
            issuer_str = ', '.join(entry.get('issuer_list', []))
            # Unir todos los Subjects en una sola cadena separada por comas
            subject_str = ', '.join(entry.get('subject_list', []))
            
            # Escribir la fila en el CSV
            writer.writerow([
                entry['dst'],
                entry['src'], 
                entry['dstport'], 
                entry['srcport'],
                ja4x_str,  # Columna JA4X
                issuer_str,  # Columna Issuer
                subject_str  # Columna Subject
            ])

# Función principal
def main():
    global fp_out, debug, mode, output_types

    parser = argparse.ArgumentParser(description="Extrae huellas JA4X de un archivo PCAP y guarda en CSV.")
    parser.add_argument("pcap", help="Archivo PCAP a procesar")
    parser.add_argument("-o", "--output", help="Archivo CSV de salida", default="output.csv")
    args = parser.parse_args()

    # Procesar el archivo PCAP
    ps = Popen(["tshark", "-r", args.pcap, "-T", "ek", "-n"], stdout=PIPE, encoding='utf-8')
    data = []

    for idx, line in enumerate(iter(ps.stdout.readline, '')): # enumerate(sys.stdin):
        if "layers" in line:
            pkt = json.loads(line)
            layers = pkt['layers'] 

            x = {}
            layer_update(x, pkt, 'frame')
            layer_update(x, pkt, 'ip') if 'ipv6' not in x['protos'] else layer_update(x, pkt, 'ipv6')

            if 'tcp' in x['protos']:
                layer_update(x, pkt, 'tcp') 
                if 'ocsp' in x['protos'] or 'x509ce' in x['protos']:
                    layer_update(x, pkt, 'x509af') 
                elif 'http' in x['protos']:
                    if 'http2' in x['protos']:
                        layer_update(x, pkt, 'http2') 
                    else:
                        layer_update(x, pkt, 'http') 
                elif 'tls' in x['protos']:
                    layer_update(x, pkt, 'tls') 
                elif 'ssh' in x['protos']:
                    layer_update(x, pkt, 'ssh')
                x['quic'] = False


            elif 'udp' in x['protos'] and 'quic' in x['protos']: 
                layer_update(x, pkt, 'udp')
                layer_update(x, pkt, 'quic')
                x['quic'] = True

            else:
                continue

            if 'stream' not in x:
                continue

            # We update the stream value into the cache first
            # to start recording this entry and then the tuple as well
            #print (idx, x['stream'], x['protos'])
            x['stream'] = int(x['stream'])

            [ cache_update(x, key, x[key]) for key in [ 'stream', 'src', 'dst', 'srcport', 'dstport', 'protos' ] ] #if x['srcport'] != '443' else None

            # Added for SSH
            if 'tcp' in x['protos'] and 'ja4ssh' in output_types:
                if (int(x['srcport']) == 22) or (int(x['dstport']) == 22):
                    cache_update(x, 'count', 0)
                    cache_update(x, 'stats', [])
                    

            # Timestamp recording happens on cache here
            # This is for TCP
            if 'tcp' in x['protos']: # and 'tls' not in x['protos']:
                if 'flags' in x:
                    flags = int(x['flags'], 0)
                    if (flags & TCP_FLAGS['SYN']) and not (flags & TCP_FLAGS['ACK']):
                        cache_update(x, 'A', x['timestamp'])
                        cache_update(x, 'timestamp', x['timestamp'])
                        cache_update(x, 'client_ttl', x['ttl']) if 'ttl' in x else None
                    if (flags & TCP_FLAGS['SYN']) and (flags & TCP_FLAGS['ACK']):
                        cache_update(x, 'B', x['timestamp'])
                        cache_update(x, 'server_ttl', x['ttl']) if 'ttl' in x else None
                    if (flags & TCP_FLAGS['ACK']) and not (flags & TCP_FLAGS['SYN']) and 'ack' in x and x['ack'] == '1' and 'seq' in x and x['seq'] == '1':
                        cache_update(x, 'C', x['timestamp'])

            # Timestamp recording for QUIC, printing of QUIC JA4 and JA4S happens
            # after we see the final D packet.
            if 'packet_type' in x:
                if x['packet_type'] == '0' and 'type' in x and x['type'] == '1':
                    cache_update(x, 'A', x['timestamp']) 
                    cache_update(x, 'client_ttl', x['ttl'])
                if x['packet_type'] == '0' and 'type' in x and x['type'] == '2':
                    cache_update(x, 'B', x['timestamp']) 
                    cache_update(x, 'server_ttl', x['ttl'])
                if x['packet_type'] == '2' and x['srcport'] == '443':
                    cache_update(x, 'C', x['timestamp']) 
                if x['packet_type'] == '2' and x['dstport'] == '443':
                    if (cache_update(x, 'D', x['timestamp'])):
                        continue

            

            if x['hl'] == 'x509af':
                to_ja4x(x) 
                #print(x)
                data.append(x)

    save_to_csv(data, args.output)
    print(f"Datos guardados en {args.output}")

if __name__ == '__main__':
    main()