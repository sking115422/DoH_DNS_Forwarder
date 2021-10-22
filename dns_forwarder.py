import socket
# import dnspython as dns
# import dns.resover
import scapy.all as scapy
import argparse
import ssl


parser = argparse.ArgumentParser(description='Run to start up a dns forwarder with DoH capabilities')

parser.add_argument('-d', action='store', dest='DST_IP', type=str, required=False, default='127.0.0.53', help='Destination DNS server IP')
parser.add_argument('-f', action='store', dest='DENY_LIST_FILE', type=str, required=False, default='./deny_list.txt', help='File containing domains to block')
parser.add_argument('-l', action='store', dest='LOG_FILE', type=str, required=False, default='./queries.log', help='Append-only log file')
parser.add_argument('--doh', action='store_true', dest='DOH', required=False, default=False, help='Use default upstream DoH server')
parser.add_argument('--doh_server', action='store', dest='DOH_SERVER', type=str, required=False, default=None, help='Use this upstream DoH server')

args = parser.parse_args()

if (args.DOH == True and args.DOH_SERVER != None and args.DST_IP != '127.0.0.53'):
    print ("Those flags are invalid...")
    print ("Please chose one flag. The --doh flag or the --doh_server flag or the -d flag.")
    exit(0)

if (args.DOH == True and args.DOH_SERVER != None):
    print ("Those flags are invalid...")
    print ("Please chose either the --doh flag or the --doh_server flag")
    exit(0)    

# Global variables
FORWARDER_IP = '127.0.0.1'
LOCAL_DNS_IP = args.DST_IP
DNS_PORT = 53
SENDING_PORT = 12345
DoH_PORT = 443
DEF_DOH_SERVER = '8.8.8.8'

def create_udp_sock (IP, PORT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP, PORT))
    print("Socket created on {0}:{1} ...".format(IP, PORT))
    return sock

def start_forwarding_udp (client_data):

    F_to_S_sock = create_udp_sock(FORWARDER_IP, SENDING_PORT)

    F_to_S_sock.sendto(client_data, (LOCAL_DNS_IP, DNS_PORT))

    server_data, server_address = F_to_S_sock.recvfrom(512)
    print ('client data: ', str(server_data))
    print ('client address: ', str(server_address))\

    return server_data


def create_ssl_socket (IP, PORT):
    hostname = IP
    context = ssl.create_default_context()
    # context.check_hostname = False
    # context.verify_mode = ssl.CERT_NONE
    # context.minimum_version = ssl.PROTOCOL_SSLv23

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((hostname, PORT))
    ssock = context.wrap_socket(sock, server_hostname=hostname)
    print(ssock.version())
    # with socket.create_connection((hostname, PORT)) as sock:
    #     with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            

    return ssock



def start_forwarding_DoH (client_data):

    content_length = len(client_data)

    hn = socket.gethostbyaddr(DEF_DOH_SERVER)

    http_header = 'POST /dns-query HTTP/1.1\r\nHost: ' + DEF_DOH_SERVER +'\r\nContent-Type: application/dns-message\r\nContent-Length: ' + str(content_length) + '\r\n\r\n'

    bin_convert = bytes(http_header, 'utf-8')
    
    http_req = bin_convert + client_data

    print(http_req)
    
    sec_sock = create_ssl_socket(DEF_DOH_SERVER, DoH_PORT)
    sec_sock.send(http_req)
    server_data = sec_sock.recv(4096)
    print (server_data)
    return server_data

    
def main():

    C_to_F_sock = create_udp_sock(FORWARDER_IP, DNS_PORT)

    while True:

        client_data, client_address = C_to_F_sock.recvfrom(512)
        print ('client data: ', str(client_data))
        print ('client address: ', str(client_address))

        if (args.DOH == False and args.DOH_SERVER == None):
            server_data = start_forwarding_udp
        else:
            server_data = start_forwarding_DoH(client_data)

        C_to_F_sock.sendto(server_data, client_address)


if __name__ == "__main__":
    main()



# https://cloudflare-dns.com/dns-query
# application/DNS-udpwireformat