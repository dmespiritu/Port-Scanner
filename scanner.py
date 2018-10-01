#This code was created by Derek Espiritu for a Pen-Testing Class
#Copyright Oct 1, 2018

#This script is to scan a port with TCP as a priority

import socket
from datetime import datetime

#Beginning of the scan
host = input ("Enter Address to Scan: ")
ip = socket.gethostbyname(host) #puts host into IPv4 format

print("-" * 80)
print("		Scanning the host -------------------------->", ip) #Helps user feel like something is happening :P 
print("-" * 80)

#Time 
t1 = datetime.now()

#Scanning code
try:
	for port in range(1,100):
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #creates sock stream
		result = sock.connect((ip,port))
		if result == 0:
			#If a socket is listening it'll print out the number
			print("\n Port $d is open -----" %(port))