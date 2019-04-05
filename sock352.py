
# CS 352 project part 2 
# this is the initial socket library for project 2 
# You wil need to fill in the various methods in this
# library 

# main libraries 
import binascii
import socket as syssock
import struct
import sys
from random import randint
import threading

# encryption libraries
import nacl.utils
import nacl.secret
import nacl.utils
from nacl.public import PrivateKey, Box

# if you want to debug and print the current stack frame 
from inspect import currentframe, getframeinfo

# these are globals to the sock352 class and
# define the UDP ports all messages are sent
# and received from

# the ports to use for the sock352 messages 
global sock352portTx
global sock352portRx
# the public and private keychains in hex format 
global publicKeysHex
global privateKeysHex

# the public and private keychains in binary format 
global publicKeys
global privateKeys

# the encryption flag 
global ENCRYPT

publicKeysHex = {} 
privateKeysHex = {} 
publicKeys = {} 
privateKeys = {}

# this is 0xEC 
ENCRYPT = 236 

# this is the structure of the sock352 packet 
PACKET_HEADER_FORMAT = '!BBBBHHLLQQLL'
PACKET_HEADER_LENGTH = struct.calcsize(PACKET_HEADER_FORMAT)

# sending and receiving ports of the socket
portTx = 0
portRx = 0

# maximum payload size
MAXIMUM_PACKET_SIZE = 64000
MAXIMUM_PAYLOAD_SIZE = MAXIMUM_PACKET_SIZE - PACKET_HEADER_LENGTH

# define all the packet bits
SOCK352_SYN = 0x01
SOCK352_FIN = 0x02
SOCK352_ACK = 0x04
SOCK352_RESET = 0x08
SOCK352_HAS_OPT = 0x10

# store the index for the flag, sequence no. and ack no. within the packet header
PACKET_FLAG_INDEX = 1
PACKET_SEQUENCE_NO_INDEX = 8
PACKET_ACK_NO_INDEX = 9

# String message to print out that a connection has been already established
CONNECTION_ALREADY_ESTABLISHED_MESSAGE = "This socket supports a maximum of one connection\n" \
                                 "And a connection is already established"


def init(UDPportTx, UDPportRx):
    global sock352portTx
    global sock352portRx

    # Sets the transmit port to 27182 (default) if its None or 0
    if UDPportTx is None or UDPportTx == 0:
        UDPportTx = 27182

    # Sets the receive port to 27182 (default) if its None or 0
    if UDPportRx is None or UDPportRx == 0:
        UDPportRx = 27182

    # Assigns the global transmit and receive ports to be the one passed in through this method
    sock352portTx = int(UDPportTx)
    sock352portRx = int(UDPportRx)

    
# read the keyfile. The result should be a private key and a keychain of
# public keys
def readKeyChain(filename):
    global publicKeysHex
    global privateKeysHex 
    global publicKeys
    global privateKeys 
    
    if (filename):
        try:
            keyfile_fd = open(filename,"r")
            for line in keyfile_fd:
                words = line.split()
                # check if a comment
                # more than 2 words, and the first word does not have a
                # hash, we may have a valid host/key pair in the keychain
                if (len(words) >= 4) and (words[0].find("#") == -1):
                    host = words[1]
                    port = words[2]
                    keyInHex = words[3]
                    if words[0] == "private":
                        privateKeysHex[(host, port)] = keyInHex
                        privateKeys[(host, port)] = nacl.public.PrivateKey(keyInHex, nacl.encoding.HexEncoder)
                    elif words[0] == "public":
                        publicKeysHex[(host, port)] = keyInHex
                        publicKeys[(host, port)] = nacl.public.PublicKey(keyInHex, nacl.encoding.HexEncoder)
        except Exception, e:
            print ("error: opening keychain file: %s %s" % (filename, repr(e)))
    else:
            print ("error: No filename presented")             

    return publicKeys, privateKeys


class socket:
    
    def __init__(self):
        # creates the socket
        self.socket = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)
        self.socket.settimeout(0.2)
        self.send_address = None
        self.is_connected = False
        self.can_close = False
        self.sequence_no = randint(1, 100000)
        self.ack_no = 0
        self.data_packets = []
        self.file_len = -1
        self.retransmit = False
        self.encrypt = False
        # the corresponding lock for the retransmit boolean
        self.retransmit_lock = threading.Lock()
        # declares the last packet that was acked (for the sender only)
        self.last_data_packet_acked = None
        
    def bind(self, address):
        self.socket.bind((address[0], portRx))

    def connect(self, *args):

        # example code to parse an argument list (use option arguments if you want)
        global sock352portTx
        global ENCRYPT
        if len(args) >= 1:
            self.send_address = args[0]
        if len(args) >= 2:
            if args[1] == ENCRYPT:
                self.encrypt = True
                
        # your code goes here 

    def listen(self,backlog):
        # listen is not used in this assignments 
        pass
    

    def accept(self,*args):
        # example code to parse an argument list (use option arguments if you want)
        global ENCRYPT
        if (len(args) >= 1):
            if (args[0] == ENCRYPT):
                self.encryption = True
        # your code goes here 

    def close(self):
        # your code goes here 
        return 

    def send(self,buffer):
        # your code goes here 
        return 

    def recv(self,nbytes):
        # your code goes here
        return 



    


