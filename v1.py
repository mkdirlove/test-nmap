from tabulate import tabulate
import argparse
import nmap
import csv

# Ascii banner
banner = """
██████╗ ███╗   ██╗███╗   ███╗ █████╗ ██████╗ 
██╔══██╗████╗  ██║████╗ ████║██╔══██╗██╔══██╗
██████╔╝██╔██╗ ██║██╔████╔██║███████║██████╔╝
██╔═══╝ ██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝ 
██║     ██║ ╚████║██║ ╚═╝ ██║██║  ██║██║     
╚═╝     ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
          Developed by @mkdirlove
          
"""

# Create an ArgumentParser
parser = argparse.ArgumentParser(description="Target Scanning using Nmap")

# Add arguments for IP address and output file
parser.add_argument("-ip", "--ip-addr", dest="ip_addr", required=True, help="Target IP address")
parser.add_argument("-o", "--output", dest="output_file", default="output_nmap.csv", help="Output CSV file")

# Parse the command-line arguments
args = parser.parse_args()

# Initialize the Nmap scanner
scanner = nmap.PortScanner()

print(banner)

ip_addr = args.ip_addr
print("Scanning IP Address: ", ip_addr)

print("Starting...")
print("Nmap Version: ", scanner.nmap_version())
scanner.scan(ip_addr, '1-65535', '-v -sS -sV -sC -A -O')
print(scanner.scaninfo())
print("Ip Status: ", scanner[ip_addr].state())
print(scanner[ip_addr].all_protocols())
open_ports = scanner[ip_addr]['tcp']

# Check if 'tcp' protocol exists in the scan results
if 'tcp' in scanner[ip_addr]:
    open_ports = scanner[ip_addr]['tcp']
    print(scanner[ip_addr].all_protocols())

    # Create a list to store the data in a tabular format
    table_data = []
    for port, info in open_ports.items():
        data = [
            ip_addr,
            info.get('hostname', ''),
            info.get('hostname_type', ''),
            'tcp',
            port,
            info.get('name', ''),
            info.get('state', ''),
            info.get('product', ''),
            info.get('extrainfo', ''),
            info.get('reason', ''),
            info.get('version', ''),
            info.get('conf', ''),
            info.get('cpe', ''),
        ]
        table_data.append(data)

    # Define the table headers
    headers = ["Host", "Hostname", "Hostname_type", "Protocol", "Port", "Name", "State", "Product", "Extrainfo", "Reason", "Version", "Conf", "Cpe"]

    # Print the table in the terminal
    print(tabulate(table_data, headers, tablefmt="grid"))

    # Write the data to the CSV file
    with open(args.output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(table_data)

    print(f"Check the output file, {args.output_file}, for detailed scan results!")
else:
    print("No open TCP ports found during the scan.")