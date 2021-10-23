import socket
import scapy.all as scapy
import argparse
import ssl
from datetime import datetime


"""

Basic DNS_Forwarder

Written By: Spencer King

This code is designed to implement a basic DNS forwarder to run on a linux server. It takes optional command line arguments from the user to specify whether to preform the DNS 
forwarding over UDP or over DoH. The program also takes in an optional list of hostnames to be blocked as a file. It will then block any domain on the list and return a NXDOMAIN
error to the client. It also logs each query in an append only log file specified by the user. 

"""


#Argparse is used here to reading command line arguments
parser = argparse.ArgumentParser(description='Run to start up a dns forwarder with DoH capabilities')

parser.add_argument('-d', action='store', dest='DST_IP', type=str, required=False, default='127.0.0.53', help='Destination DNS server IP')
parser.add_argument('-f', action='store', dest='DENY_LIST_FILE', type=str, required=False, default='./deny_list.txt', help='File containing domains to block')
parser.add_argument('-l', action='store', dest='LOG_FILE', type=str, required=False, default='./queries.log', help='Append-only log file')
parser.add_argument('--doh', action='store_true', dest='DOH', required=False, default=False, help='Use default upstream DoH server')
parser.add_argument('--doh_server', action='store', dest='DOH_SERVER', type=str, required=False, default=None, help='Use this upstream DoH server')

args = parser.parse_args()

#Error handling in case user miss enters command line flags or arguments
if (args.DOH == True and args.DOH_SERVER != None and args.DST_IP != '127.0.0.53'):
    print ("Those flags are invalid...")
    print ("Please chose one flag. The --doh flag or the --doh_server flag or the -d flag.")
    exit(0)

if (args.DOH == True and args.DOH_SERVER != None):
    print ("Those flags are invalid...")
    print ("Please chose either the --doh flag or the --doh_server flag")
    exit(0) 


### GLOBAL VARIABLES
#GENERAL
FORWARDER_IP = '127.0.0.1'
DENY_LIST_FILENAME = args.DENY_LIST_FILE
LOG_FILENAME = args.LOG_FILE

#UDP
LOCAL_DNS_IP = args.DST_IP
DNS_PORT = 53
SENDING_PORT = 12345

#DOH
DoH_PORT = 443

#Allowing user to set desired DoH server or selecting 8.8.8.8 (Google DoH Server) as default
if (args.DOH == True):
    DEF_DOH_SERVER = '8.8.8.8'

if (args.DOH_SERVER != None): 
    DEF_DOH_SERVER = args.DOH_SERVER

#Creating UDP socket
def create_udp_sock (IP, PORT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP, PORT))

    print("Socket created on {0}:{1}".format(IP, PORT))
    
    return sock

#Forwarding client request and receiving server response over UDP 
def start_forwarding_udp (client_data):

    F_to_S_sock = create_udp_sock(FORWARDER_IP, SENDING_PORT)

    F_to_S_sock.sendto(client_data, (LOCAL_DNS_IP, DNS_PORT))
    print("Forwarding request via UDP to local DNS server " + LOCAL_DNS_IP + " on port " + str(DNS_PORT))
    server_data, server_address = F_to_S_sock.recvfrom(512)
    print("Successfully recieved response back from server")

    return server_data

#Creating secure socket with TLS session
def create_ssl_socket (IP, PORT):
    hostname = IP
    context = ssl.create_default_context()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((hostname, PORT))
    ssock = context.wrap_socket(sock, server_hostname=hostname)
    print("TLS session: " + ssock.version() + " started with DoH server " + DEF_DOH_SERVER + " on port " + str(DoH_PORT))
            
    return ssock

#Forwarding client request and receiving server response over DoH 
def start_forwarding_DoH (client_data):

    content_length = len(client_data)
    http_header = 'POST /dns-query HTTP/1.1\r\nHost: ' + DEF_DOH_SERVER +'\r\nContent-Type: application/dns-message\r\nContent-Length: ' + str(content_length) + '\r\n\r\n'
    bin_convert = bytes(http_header, 'utf-8')
    http_req = bin_convert + client_data
    
    sec_sock = create_ssl_socket(DEF_DOH_SERVER, DoH_PORT)
    sec_sock.send(http_req)
    print ("DoH request successfully forwarded to local DoH server")
    server_data = sec_sock.recv(4096)
    print ("DoH response successfully recieved from local DoH server")

    rtn_char = '\r\n\r\n'.encode('utf-8')
    parts = server_data.split(rtn_char)
    DNS_response = parts[1]
    
    return DNS_response

#Checking client query against blocked hostnames and return mock NXDOMAIN server response error if denied
def check_blocked_IPs (client_data):

    packet = scapy.DNS(client_data)

    raw_hostname = packet.sprintf("qd = %qd%")

    parts = raw_hostname.split()
    temp = parts[3]
    hostname = temp[7:-2]

    temp2 = parts[4]
    query_type = temp2[6:]

    file = open(DENY_LIST_FILENAME, "r")
    text = file.read()
    lines = text.split('\n')
    file.close()

    status = "ALLOW"
    block = False

    for each in lines:
        each.strip()
        if hostname == each:
            block = True

    if (block == False):
        return None, hostname, query_type, status
    else:
        packet_id = int(packet.sprintf("%id%"))

        dns_req = scapy.DNS(id = packet_id, qr = 1, opcode = 0000, rd = 1, ra = 1, rcode = 3, qd = scapy.DNSQR(qname=hostname, qtype = query_type))

        resp = bytes(dns_req)
        # print("DNS request was either not found or blocked")

        status = "DENY"

        return resp, hostname, query_type, status

#Logging each query as allowed or denied and timestamping it
def log_query (hostname, query_type, status):
    
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y|%H:%M:%S")

    file = open(LOG_FILENAME, "a")
    entry = dt_string + " " + hostname + " " + query_type  + " " + status + " \n"
    file.write(entry)
    file.close()

    print ("Query successfully logged in " + LOG_FILENAME)

### DRIVER FUNCTION
def main():
    
    #Creating socket to listen for client DNS quieries on port 53
    print()
    C_to_F_sock = create_udp_sock(FORWARDER_IP, DNS_PORT)
    print("Now listening for DNS requests...")
    print()

    #Starting forwarder
    while True:

        #Recieving client query data and address
        client_data, client_address = C_to_F_sock.recvfrom(512)

        #Checking if client query is allowed
        resp, hostname, query_type, status = check_blocked_IPs(client_data)

        #Logging query and status as allowed or denied
        log_query(hostname, query_type, status)

        #If query is not allowed, an error response is sent back to the client
        if (resp != None):
            C_to_F_sock.sendto(resp, client_address)
            print("DNS request was either not found or blocked\n")
            continue
        
        #If query is allowed and client has chosen UDP, forwarder will send and recieve over UDP
        if (args.DOH == False and args.DOH_SERVER == None):
            server_data = start_forwarding_udp (client_data)
        #If query is allowed and client has chosen DoH, forwarder will send and recieve over DoH
        else:
            server_data = start_forwarding_DoH (client_data)
        
        #Sending final response from local server back to client
        C_to_F_sock.sendto(server_data, client_address)
        print ("Local server response successfully sent back to client\n")


if __name__ == "__main__":
    main()


# DoH Server List:
# Google - 8.8.8.8
# Cloudflare - 1.0.0.1 