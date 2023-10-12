import argparse
import nmap
import csv

# Create an ArgumentParser
parser = argparse.ArgumentParser(description="Target Scanning using Nmap")

# Add arguments for IP address and output file
parser.add_argument("-ip", "--ip-addr", dest="ip_addr", required=True, help="Target IP address")
parser.add_argument("-o", "--output", dest="output_file", default="scan_report.csv", help="Output CSV file")

# Parse the command-line arguments
args = parser.parse_args()

# Initialize the Nmap scanner
scanner = nmap.PortScanner()

print("Target Scanning using Nmap")
print("<----------------------------------------------------->")

ip_addr = args.ip_addr
print("The IP you entered is: ", ip_addr)

print("Starting..")
print("Nmap Version: ", scanner.nmap_version())
scanner.scan(ip_addr, '1-65535', '-v -sS -sV -sC -A -O')
print(scanner.scaninfo())
print("Ip Status: ", scanner[ip_addr].state())
print(scanner[ip_addr].all_protocols())
print("Open Ports: ", scanner[ip_addr]['tcp'].keys())

output = scanner.csv()

l = list(output.split("\n"))

for i in range(len(l)):
    l[i] = l[i].split(";")

with open(args.output_file, 'w') as f:
    writer = csv.writer(f)
    writer.writerows(l)

print(f"Check the output file, {args.output_file}, for detailed scan results!")
