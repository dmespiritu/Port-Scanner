#DAVID GREERS CODE THAT I USED FOR HELP 

from scapy.all import *
import argparse
import os
import subprocess
import ipaddress
import socket
import sys
import matplotlib.pyplot as plt
import datetime
from webbrowser import open_new_tab

# basic description of the scripts functions
description= "Penetration testing port/ip scanner"
# parses the flags for me so I don't have to
argument_parser = argparse.ArgumentParser(description = description)

# flags that must be set
argument_parser.add_argument("-ip_addr",metavar ='I', help="ip_address(es) to scan: format can be a single address, comma seperated,'-' seperated,CIDR",nargs='?', const ="127.0.0.1")
argument_parser.add_argument("-po",help="port(s) to scan: format can be [p, 1 - n , comma seperated]", nargs='?', const ="80")

#add list of argumens that can be passed aswell as there helpmenu text
argument_parser.add_argument("-tcp","--tcp_scan",help = "perform a tcp port(s) scan", action="store_true" )
argument_parser.add_argument("-udp","--udp_scan",help = "perform a udp port(s) scan", action="store_true" )
argument_parser.add_argument("-trace", "--trace_route", help="perform a traceroute", action="store_true")
argument_parser.add_argument("-ps", "--ping_sweep", help="perform a ping rquest/sweep", action="store_true")

# Port scan for TCP
def tcp_scan(hosts, ports):
    print ("\033[1;34;40m******Starting TCP scan****** \033[0m")
    results = {}

    # if no port was entered
    if ports is []:
        print("Error: Ports are needed to complete this scan")
        return ''

    for host in hosts:
        results[host] = []
        for port in ports:
            loading_indicator()

            # using sockets to scan the port
            sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            result = sock.connect_ex( (socket.gethostbyname(host),int(port)  ))

            #if an error didn't occur(the request succeeded) and that message is stored in the resuls
            if result == 0: results[host].append("{:<6} |{:<4}\t|\033 {:<14}".format(port,"tcp","open"))

            #else store the closed port response in the results
            else: results[host].append("{:<6} |{:<4}\t|\033[1;31;40m {:<14} \033[0m".format(port,"tcp","closed"))
            sock.close()
    return results

# Port Scan for UDP
def udp_scan(hosts, ports):
    print("\033[1;34;40m******Starting UDP Scan****** \033[0m")
    results = {}

    # if no port was entered
    if ports is []:
        print("Error: Ports are needed to complete this scan")
        return ''

    for host in hosts:

        results[host] = []
        for port in ports:
            loading_indicator()

            # creating the ip and udp info
            ip = IP(dst=host)
            udp = UDP(dport=int(port),sport = 123)

            # creating the packet and get the response
            packet = ip/udp
            response = sr(packet,verbose=False,timeout = 20)

            # check for an ICMP packet, if it errors one wasn't sent and the port is open |filtered
            try:
                check = response[0][ICMP][0][1][ICMP]
                results[host].append(" {:<6} |{:<4}\t|\033[1;31;40m {:<14} \033[0m".format(port,"udp","closed"))
            except IndexError:
                results[host].append(" {:<6} |{:<4}\t|\033[1;33;40m {:<14} \033[0m".format(port,"udp","open|filtered"))


    return results

# Poor mans loading screen
def loading_indicator():
    sys.stdout.write(".")
    sys.stdout.flush()

# performs a traceroute
def trace_route(hosts,ports):

    print ("\033[1;34;40m******Starting traceroute****** \033[0m")
    results = {}

    for host in hosts:
        loading_indicator()
        results[host] = []
        proc = subprocess.Popen("tracert -d %s" % host, shell=True,stdout=subprocess.PIPE)

        # read the response from the traceroute
        while True:
            line = proc.stdout.readline().decode("utf-8")

            if "Trace complete." not in line.strip():
                results[host].append(line.strip())

            if not line: break

        proc.wait()
    return results

# performs a ping sweep on up to n ips
def ping_sweep(hosts,ports):

    print ("\033[1;34;40m******Starting ping sweep****** \033[0m")
    results = {}

    for host in hosts:
        loading_indicator()
        results[host] = []
        ping = ['ping','-n','1',"-w","20",host]

        # perform a the ping request
        output = subprocess.Popen(ping,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True).communicate()
        output_string = output[0].decode("utf-8")

        # if the response says lost = 0 the host is alive and well
        if "Lost = 0" in output_string:
            results[host].append("\033[1;33;40m"+host + "\033[0m is online")
        else:
            results[host].append("\033[1;33;40m"+host + "\033[0m is \033[1;31;40moffline \033[0m")
    return results

# used to parse and format ips given by the user
def parse_hosts(ip_addr):

    if "/" in ip_addr:
        subnet = ipaddress.ip_network(ip_addr)
        return [ host.__str__() for host in list(subnet.hosts()) ]

    #values are seperated by a comma
    if "," in ip_addr: return ip_addr.split(",")

    #values are seperated by "-"
    if "-" in ip_addr:
        host_list = []
        ip_range = ip_addr.split("-")
        octet_breakdown = ip_range[0].split(".")

        # get the first and last octet of the ip range
        first_host = int(octet_breakdown[3])
        last_host = int(ip_range[1])

        octet_range = list(range(first_host,last_host+1))

        # the next two lines just gets the first 3 octets joins them and then outputs the range
        octet_breakdown.pop()
        host_network = ".".join(octet_breakdown)

        # generates the ip range but only by the last octet
        for value in octet_range:
            host_list.append(host_network + "." +str(value))
        return host_list

    #only one host ip was entered
    return [ip_addr]

# used to parse and format ports given by the user
def parse_ports(ports):
    ports_list = []
    if ports is None: return []

    if "," in ports:
         #convert ports string to a int list
        ports_list = [ int(port) for port in ports.split(",") ]

    elif "-" in ports:
        #convert ports string range to an int list
        ports_list = ports.split("-")
        ports_list  = list(range( int(ports_list[0] ), int( ports_list[1] ) +1 ) )

    else:
        #only one port was entered
        return [ports]


    return ports_list

# prints the results for the command prompt
def print_results(result_dict):

    for host in result_dict:
        print("\nTARGET HOST:" + host)

        # print out the results of the scan(this is a 1 line for loop :)
        [print(result_text) for result_text in result_dict[host]]

    print("\n\033[1;34;40m******End****** \033[0m \n")


# Convert the argument_parser arguements dictionary to a dictionary
arguements_dict = vars(argument_parser.parse_args())

# Parses the user input for the ip addresses and ports
hosts =  parse_hosts(arguements_dict['ip_addr'])
ports = parse_ports(arguements_dict['po'])

#loop through all of the tags created by the arguement parser namespace
for arguement in arguements_dict:

    # call the local functions in this script by name when their coorisponding flag is set
    if arguements_dict[arguement] is True:
        response = locals()[arguement]( hosts , ports )
        print_results(response)
