#!/usr/bin/env python3

import sys
import csv
import os
import re
import hashlib
import argparse
from collections import defaultdict


delim = ";"
adlist = "/../utils/ad-list.txt"
tls_db = defaultdict(str)     # a hash array of all processed TLS handshakes
short_db = defaultdict(str)  # a hash array of unique entries of the short list


GREASE_HEX = ["0x0a0a", "0x1a1a", "0x2a2a", "0x3a3a", "0x4a4a", "0x5a5a", "0x6a6a", "0x7a7a", "0x8a8a", "0x9a9a", "0xaaaa", "0xbaba", "0xcaca", "0xdada", "0xeaea", "0xfafa"]
GREASE = [2570, 6682, 10794, 14906, 19018, 23130, 27242, 31354, 35466, 39578, 43690, 47802, 51914, 56026, 60138, 64250]

TLS_MAPPER = {
    '256': "s1", '512': "s2", '0x0300': "s3", '0x0301': "10", 
    '0x0302': "11", '0x0303': "12", '0x0304': "13"
}


def md5_hex(s):
    return hashlib.md5(s.encode()).hexdigest()

def sha256_hex(s):
    return hashlib.sha256(s.encode()).hexdigest()


def load_adlist():
    try:
        addservers = {}
        with open(adlist, "r") as adfile:
            for line in adfile:
                line = line.strip()
                addservers[line] = 1
        return addservers
    except FileNotFoundError:
        print(f"Warning: {adlist} not found. Skipping ad-list processing.")
        return {}

def load_whois_file(whoisfile):
    try:
        whois_db = {}
        with open(whoisfile, 'r') as file:
            for line in file:
                parts = line.strip().split(';')
                if len(parts) == 2:
                    whois_db[parts[0]] = parts[1]
        return whois_db
    except FileNotFoundError:
        print(f"Warning: {whoisfile} not found. Skipping ad-list processing.")
        return {}

def load_resolution_file(resfile):
    try:
        res_db = {}
        with open(resfile, 'r') as file:
            for line in file:
                parts = line.strip().split(',')
                if len(parts) == 2:
                    res_db[parts[0]] = parts[1]
        return res_db
    except FileNotFoundError:
        print(f"Warning: {resfile} not found. Skipping ad-list processing.")
        return {}

def process_tls_file(filename, short=False, app_name="Unknown", version="0", traffic_type="0", resfile=None, whoisfile=None, adfile=None):
    whois_db = {}
    res_db = {}
    adservers = {}

    file_name = os.path.splitext(os.path.basename(filename))[0]

    # Cargar archivos adicionales si es necesario
    if whoisfile:
        whois_db = load_whois_file(whoisfile)
    
    if resfile:
        res_db = load_resolution_file(resfile)
    
    if adfile:
        addservers = load_adlist()
    
    with open(filename, 'r') as file:
        reader = csv.reader(file, delimiter=';')
        header = next(reader)  # Skip header
        #print(f"Encabezado {header}")

        for row in reader:
            srcIP, dstIP, srcTCPort, dstTCPort, srcUDPort, dstUDPort, proto, type_, version_, cipher_suite, extensions, sni, supported_groups, ec_format, alpn, sig, supported_versions, time = row
            app_type = traffic_type

            
            

            org_name = whois_db.get(dstIP, "") # resolve the dstIP using the WHOIS database

            # Analizar las comunicaciones TLS
            if proto == '6':  # TCP (TLS over TCP)
                ja4_protocol = "t"
                srcPort = int(srcTCPort)
                dstPort = int(dstTCPort)
            else:  # UDP (QUIC over UDP)
                ja4_protocol = "q"
                srcPort = int(srcUDPort)
                dstPort = int(dstUDPort)
            
            if res_db.get(srcPort): # check if the local port can be mapped to an application
                app_type = "0"
                app_name = res_db[srcPort] # assign the mapping from the external resolution file
                #print(f"resolution for port {srcPort}: app_name = {app_name}\n")
            
            # TLS handshake type (Client Hello = 1, Server Hello = 2)
            type_ = type_.split(",")[0] # in case of the Server Hello, more types can be included into one packet. Only first value interesting
            version = int(version_, 16)
            ja4_cipher_suite = cipher_suite
            

            if sni: # set the SNI to "d" (domain) if SNI is non-empty or to "i" (IP) if empty
                ja4_sni = "d"
                if sni in adservers: # if a SNI is in the ad-list file, the TLS fingerprint is marked as "A" (ads)
                    app_type = "A"
            else:
                ja4_sni = "i"
            #print(f"SNI {ja4_sni}\n")

            if not alpn:
                alpn = "00"         # if empty, set the predefined value
                full_alpn = ""      # initialize the full ALPN string
            else:
                full_alpn = alpn   
                alpn_list = alpn.split(",")   
                alpn = alpn_list[0]         # if non-empty, select the first value in the list
                if len(alpn) > 2:
                    alpn = alpn[0] + alpn[-1]   # if a string is too short, map it to two chars
            #print(f"ALPN {alpn}\n")

            #SIG: a list of hash algorithms for JA4 signature (extension type 0x0d = 13)
            ja4_version = supported_versions            # a list of supported versions (extension type 0x2b = 43)
            supported_versions = supported_versions     # keeps original value for the extended output CSV

            suites = cipher_suite.split(",")            
            cipher_suite_dec = "-".join([str(int(s, 16)) for s in suites])   # convert the cipher suites from hex to decimal format for JA3 hash

            extensions = extensions.replace(",", "-") # JA4 hash expects a list of extensions separated by '-'
            for grease in GREASE:                     # exclude GREASE values from the cipher_suites and extensions for JA3
                cipher_suite_dec = re.sub(f"{grease}-?", "", cipher_suite_dec)
                extensions = re.sub(f"{grease}-?", "", extensions)

            for grease_hex in GREASE_HEX:            # exclude GREASE_HEX values from cipher_suites and supported_versions for JA4
                ja4_cipher_suite = re.sub(f"{grease_hex},?", "", ja4_cipher_suite)
                ja4_version = re.sub(f"{grease_hex},?", "", ja4_version)   
            
            suites = ja4_cipher_suite.split(",")    # processing JA4 cipher suites
            cipher_sorted = sorted(suites)          # sort the cipher suites for JA4 Client Hello
            ja4_cipher_suite = ",".join(cipher_sorted).replace("0x", "")   # remove 0x prefix in hex numbers


            if not ja4_version:                         # if extension supported_versions is not present
                ja4_version = f"0x{version:04x}"        # use the handshake TLS version converted to hex
            else:
                sup_versions = ja4_version.split(",")
                ver_sorted = sorted(sup_versions)      # select the max SSL version from the supported groups
                ja4_version = ver_sorted[-1]           # the highest value of the sorted list has the last index
            

            ja4_version = TLS_MAPPER.get(ja4_version, "00")     # map the TLS value to the JA4 string 00 if current TLS version not found in the list

            ja4_suites_no = len(ja4_cipher_suite.split(","))    # count the number of cipher suites separated by ","
            ja4_suites_no = f"{ja4_suites_no:02d}"              # two digit number is expected


            ext = extensions.split("-")
            if type_ == "1":  # Client Hello -> sorted list required    
                ext = [e for e in ext if e.strip() and e.isdigit()]  # Filtra cadenas vacías y no numéricas
                ext_sorted = sorted(ext, key=int)
            else:  # Server Hello -> the order of extensions preserved
                ext_sorted = ext
            
            ja4_ext_no = f"{len(ext_sorted):02d}"   # the number of extensions
            ja4_ext = ",".join([f"{int(e):04x}" for e in ext_sorted if e and f"{int(e):04x}" not in ["0000", "0010"]])


            sig = sig.replace("0x", "")

            groups = supported_groups.split(",")
            # Filtrar valores vacíos antes de la conversión
            groups = [g for g in groups if g.strip()]  
            sg = "-".join([str(int(g, 16)) for g in groups]) if groups else "0"  # convert decimal extension to hexadecimal

            for grease in GREASE:                               # exclude GREASE values from the supported groups
                sg = re.sub(f"{grease}-?", "", sg)
            

            # compute JA3, JA4, JA3S and JA4S hashes

            if type_ == "1":  # Client Hello fingerprints JA3 and JA4
                key = f"{srcIP}:{dstIP}:{srcPort}"                                                  # compute a hash key for the Client Hello for tls_db
                ja3 = md5_hex(f"{version},{cipher_suite_dec},{extensions},{sg},{ec_format}")        # compute the JA3 client fingerprint
                # compute the JA4 client fingerpring
                ja4_a = f"{ja4_protocol}{ja4_version}{ja4_sni}{ja4_suites_no}{ja4_ext_no}{alpn}"    
                ja4_b = sha256_hex(ja4_cipher_suite)[:12]
                ja4_c = sha256_hex(f"{ja4_ext}_{sig}")[:12]
                # raw format
                ja4_r = f"{ja4_a}_{ja4_cipher_suite}_{ja4_ext}_{sig}"
                # hash format
                ja4 = f"{ja4_a}_{ja4_b}_{ja4_c}"

                # create a new entry
                if short:
                    entry = f"{srcIP}{delim}{dstIP}{delim}{srcPort}{delim}{dstPort}{delim}{sni}{delim}{org_name}{delim}{ja3}{delim}{ja4}{delim}{app_name}{delim}{app_type}"
                else:
                    entry = f"{srcIP}{delim}{dstIP}{delim}{srcPort}{delim}{dstPort}{delim}{proto}{delim}{sni}{delim}{org_name}{delim}{version}{delim}{cipher_suite_dec}{delim}{extensions}{delim}{supported_groups}{delim}{ec_format}{delim}{full_alpn}{delim}{sig}{delim}{supported_versions}{delim}{ja3}{delim}{ja4}{delim}{ja4_r}{delim}{app_name}{delim}{app_type}"
                # insert a new entry into the TLS hash array
                tls_db[key] = entry
            
            else:  # Server Hello fingerprints JA3s and JA4s
                ja3s = md5_hex(f"{version},{cipher_suite_dec},{extensions}")      # compute the JA3 server fingerprint  
                # compute the JA4 server fingerprint
                ja4_a = f"{ja4_protocol}{ja4_version}{ja4_ext_no}{alpn}"
                ja4_b = ja4_cipher_suite
                ja4_c = sha256_hex(ja4_ext)[:12]
                # raw format
                ja4s_r = f"{ja4_a}_{ja4_b}_{ja4_ext}"
                # hash format
                ja4s = f"{ja4_a}_{ja4_b}_{ja4_c}"
                # compute a hash key for the Server Hello for %tls_db
                key = f"{dstIP}:{srcIP}:{dstPort}"

                if key in tls_db:   # if a Client Hello exists in the db
                    entry = tls_db[key]     # add data from the Server Hello to the entry
                    count = entry.count(delim)  # check the number of delimiters in the entry
                    if short:
                        if count > 9:   # 9 - max delimiters for the preprocessed client hello (for raw output)	
                            return
                        tls_db[key] = f"{entry}{delim}{ja3s}{delim}{ja4s}{delim}{file_name}{delim}{version}"
                    else:
                        if count > 19:  # 19 - max delimiters for the preprocessed client hello (for raw output)
                            return
                        # process only client entries without the server part (skip duplicated server Hello)
                        tls_db[key] = f"{entry}{delim}{cipher_suite_dec}{delim}{extensions}{delim}{supported_versions}{delim}{ja3s}{delim}{ja4s}{delim}{ja4s_r}{delim}{file_name}{delim}{version}"




def parse_args():
    parser = argparse.ArgumentParser(description="Parser for TLS Client and Server Hellos to calculate JA4 and JA4S hashes.")
    parser.add_argument("-f", "--file", required=True, help="Input CSV file (output from tshark)")
    parser.add_argument("-short", action="store_true", help="Print short output")
    parser.add_argument("-app", type=str, help="Application name")
    parser.add_argument("-ver", type=str, default="0", help="Version")
    parser.add_argument("-type", choices=['0', 'A', 'M'], default="0", help="Traffic type: 0 (normal), A (analytics), M (malware)")
    parser.add_argument("-res", type=str, help="Resolution file (maps ports to process names)")
    parser.add_argument("-whois", type=str, help="WHOIS file (maps IP to organization)")
    parser.add_argument("-adlist", type=str, help="Ad list file (contains ad server domain names)")
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_args()
    process_tls_file(args.file, short=args.short, app_name=args.app, version=args.ver, traffic_type=args.type,
                     resfile=args.res, whoisfile=args.whois, adfile=args.adlist)

    if args.short:
        print(f"SrcIP{delim}DstIP{delim}SrcPort{delim}DstPort{delim}SNI{delim}OrgName{delim}JA3hash{delim}JA4hash{delim}AppName{delim}Type{delim}JA3Shash{delim}JA4Shash{delim}Filename{delim}Version")
    else:
        print(f"SrcIP{delim}DstIP{delim}SrcPort{delim}DstPort{delim}Proto{delim}SNI{delim}OrgName{delim}TLSVersion{delim}ClientCipherSuite{delim}ClientExtensions{delim}ClientSupportedGroups{delim}EC_fmt{delim}ALPN{delim}SignatureAlgorithms{delim}ClientSupportedVersions{delim}JA3hash{delim}JA4hash{delim}JA4_raw{delim}AppName{delim}Type{delim}ServerCipherSuite{delim}ServerExtensions{delim}ServerSupportedVersions{delim}JA3Shash{delim}JA4Shash{delim}JA4S_raw{delim}Filename{delim}Version")

    for key in sorted(tls_db.keys()):
        print(tls_db[key])
    
    
    