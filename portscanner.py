import nmap

scanner= nmap.PortScanner()

print ("port scanner")

ip_addr = input("entra l'indirizzo che vuoi scannerizzare:")
print ("l'indirizzo ip che hai inserito è: ", ip_addr)
type (ip_addr)

resp = input (""" \ninserire il tipo di scan che si preferisce usare
                     1)SYN ACK Scan
                     2)UDP San
                     3)Comprehensive Scan""")

print ("hai scelto l'opzione", resp)

if resp== '1':
   print ("SYN ACK Scan", scanner.nmap_version())
   scanner.scan(ip_addr, '1-1024', '-v -sS')
   print (scanner.scaninfo())
   print ("Ip Status: ", scanner [ip_addr].state())
   print (scanner[ip_addr]).all_protocols())
   print ("Open Ports:", scanner)[ip_addr] ['tcp'].keys())
elif resp == '2':
   print ("UDP Scan", scanner.nmap_version())
   scanner.scan(ip_addr, '1-1024', '-v -sU')
   print (scanner.scaninfo())
   print ("Ip Status: ", scanner [ip_addr].state())
   print (scanner[ip_addr]).all_protocols())
   print ("Open Ports:", scanner)[ip_addr] ['udp'].keys())ù
elif resp == '3':
print ("SYN ACK Scan", scanner.nmap_version())
   scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
   print (scanner.scaninfo())
   print ("Ip Status: ", scanner [ip_addr].state())
   print (scanner[ip_addr]).all_protocols())
   print ("Open Ports:", scanner)[ip_addr] ['tcp'].keys())
