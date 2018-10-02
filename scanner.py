#This code was created by Derek Espiritu for a Pen-Testing Class
#Copyright Oct 1, 2018

#This script is to scan a port with TCP as a priority

import socket
from datetime import datetime
import threading
from queue import Queue
import subprocess
import sys
import argparse

#Parse Arguments to help out with the functionality of the script
#parser = argparse.ArgumentParser(description = 'Python port scanner that uses sockets to connect and identify ports that are opened and closed')
#parser.add_argument('String', metavar='S', type =str, nargs='+', help ='string to enter in as IP address')
#args = parser.parse_args()
#print(args.accumulate(args.String))


print_lock = threading.Lock()
#Beginning of the scan
host = raw_input ("Enter Address to Scan: ")
ip = socket.gethostbyname(host) #puts host into IPv4 format

print("-" * 80)
print("		Scanning the host -------------------------->", ip) #Helps user feel like something is happening :P 
print("-" * 80)

#Time 
t1 = datetime.now()

#Scanning code
try:
	for port in range(1024):
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #creates sock stream
		result = sock.connect((ip,port))
		if result == 0:
			#If a socket is listening it'll print out the number
			print("\n Port %d is open -----" %(port))
			sock.close()
		else:
			print("\n Port %d is closed -----"%(port))
except:
	pass

def thread():
	while True:
		work = q.get()
		scan(work) #scan becomes a function with a job with available process in queue
		q.task_done()

q = Queue()

#threads allowed code
for x in range(60):
	t = threading.Thread(target=threader)
	t.daemon=True
	t.start()

for work in range(1,100):
	q.put(work)

#thread joins
q.join()		

#Show time  executed
t2 = datetime.now()
total = t2 - t1
print("Total Scanning Time: ", total)
