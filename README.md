# DoH_DNS_Forwarder

## Basic DNS Forwarder
This code is designed to implement a basic DNS forwarder to run on a linux server. It takes optional command line arguments from the user to specify whether to preform the DNS 
forwarding over UDP or over DoH. The program also takes in an optional list of hostnames to be blocked as a file. It will then block any domain on the list and return a NXDOMAIN
error to the client. It also logs each query in an append only log file specified by the user.

I have included an example deny list as "deny_list.txt" and an example log file as "queries.log" in this file for reference

## How to Run

Can be run from the command line with the following arguments:

usage: dns_forwarder.py [-h] [-d DST_IP] [-f DENY_LIST_FILE] [-l LOG_FILE] [--doh] [--doh_server DOH_SERVER]

Run to start up a dns forwarder with DoH capabilities

optional arguments:
  * -h, --help                show this help message and exit
  * -d DST_IP                 Destination DNS server IP
  * -f DENY_LIST_FILE         File containing domains to block
  * -l LOG_FILE               Append-only log file
  * --doh                     Use default upstream DoH server
  * --doh_server DOH_SERVER   Use this upstream DoH server

## Example Command Line Syntax

sudo python3 ./dns_forwarder.py --doh_server 8.8.8.8 -l queries.log -f deny_list.txt