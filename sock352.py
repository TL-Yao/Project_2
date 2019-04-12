
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
global client_box

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
    global portTx
    global portRx

    # Sets the transmit port to 27182 (default) if its None or 0
    if UDPportTx is None or UDPportTx == 0:
        UDPportTx = 27182

    # Sets the receive port to 27182 (default) if its None or 0
    if UDPportRx is None or UDPportRx == 0:
        UDPportRx = 27182

    # Assigns the global transmit and receive ports to be the one passed in through this method
    portTx = int(UDPportTx)
    portRx = int(UDPportRx)

    
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

        global portTx,portRx, client_box
        global ENCRYPT

        # example code to parse an argument list (use option arguments if you want)  
        if len(args) >= 1:
            self.send_address = args[0][0]
            self.socket.bind((args[0][0], portRx))
            if self.is_connected:
                print (CONNECTION_ALREADY_ESTABLISHED_MESSAGE)
                return

            #Three handshake:

            # Step 1: Request to connect to the server by setting the SYN flag
            # first the packet is created using createPacket and passing in the apprpriate variables
            syn_packet = self.createPacket(flags=SOCK352_SYN, sequence_no=self.sequence_no)
            self.socket.sendto(syn_packet, self.send_address)
            # increments the sequence since it was consumed in creation of the SYN packet
            self.sequence_no += 1

            received_handshake_packet = False
            while not received_handshake_packet:
                try:
                    # tries to receive a SYN/ACK packet from the server using recvfrom and unpacks it
                    (syn_ack_packet, addr) = self.socket.recvfrom(PACKET_HEADER_LENGTH)
                    syn_ack_packet = struct.unpack(PACKET_HEADER_FORMAT, syn_ack_packet)
                    # if it receives a reset marked flag for any reason, abort the handshake
                    if syn_ack_packet[PACKET_FLAG_INDEX] == SOCK352_RESET:
                        print "Connection was reset by the server"
                        return

                    # if it receives a packet, and it is SYN/ACK, we are done
                    if syn_ack_packet[PACKET_FLAG_INDEX] == SOCK352_SYN | SOCK352_ACK:
                        received_handshake_packet = True

                    # if it receives a packet with an incorrect ACK from its sequence number,
                    # it tries to receive more packets
                    if syn_ack_packet[PACKET_ACK_NO_INDEX] != self.sequence_no:
                        received_handshake_packet = False
                # retransmits the SYN packet in case of timeout when receiving a SYN/ACK from the server
                except syssock.timeout:
                    self.socket.sendto(syn_packet, self.send_address)

            # sets the client's acknowledgement number to be SYN/ACK packet's sequence number + 1
            self.ack_no = syn_ack_packet[PACKET_SEQUENCE_NO_INDEX] + 1

            # Step 3: Send a packet with the ACK flag set to acknowledge the SYN/ACK packet
            ack_packet = self.createPacket(flags=SOCK352_ACK,
                                           sequence_no=self.sequence_no,
                                           ack_no=self.ack_no)
            # increments the sequence number as it was consumed by the ACK packet
            self.sequence_no += 1

            # sets the connected boolean to be true
            self.is_connected = True

            # sends the ack packet to the server, as it assumes it's connected now
            self.socket.sendto(ack_packet, self.send_address)
            print ("Client is now connected to the server at %s:%s" % (self.send_address[0], self.send_address[1]))

            #if encryption           
            if len(args) >= 2:
                if args[1] == ENCRYPT:
                    self.encrypt = True
                    if not privateKeys[(args[0][0],portTx)] or not publicKeys[args[0]]:
                        print("Key not found")
                        return
                    else:
                        clientSk = privateKeys[(args[0][0],portTx)]
                        serverPk = publicKeys[args[0]]
                        clinet_box = Box(clientSk, serverPk)
                        nonce = nacl.utils.random(Box.NONCE_SIZE)


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

    # creates a generic packet to be sent using parameters that are
    # relevant to Part 1. The default values are specified above in case one or more parameters are not used
    def createPacket(self, flags=0x0, sequence_no=0x0, ack_no=0x0, payload_len=0x0):
        return struct.Struct(PACKET_HEADER_FORMAT).pack \
            (
                0x1,  # version
                flags,  # flags
                0x0,  # opt_ptr
                0x0,  # protocol
                PACKET_HEADER_LENGTH,  # header_len
                0x0,  # checksum
                0x0,  # source_port
                0x0,  # dest_port
                sequence_no,  # sequence_no
                ack_no,  # ack_no
                0x0,  # window
                payload_len  # payload_len
            )



    


