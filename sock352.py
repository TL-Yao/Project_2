
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

# Box
server_box = None

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
        global ENCRYPT, server_box

        # makes sure again that the server is not already connected
        # because part 1 supports a single connection only
        if self.is_connected:
            print (CONNECTION_ALREADY_ESTABLISHED_MESSAGE)
            return

        # Keeps trying to receive the request to connect from a potential client until we get a connection request
        got_connection_request = False
        while not got_connection_request:
            try:
                # tries to receive a potential SYN packet and unpacks it
                (syn_packet, addr) = self.socket.recvfrom(PACKET_HEADER_LENGTH)
                syn_packet = struct.unpack(PACKET_HEADER_FORMAT, syn_packet)

                # if the received packet is not a SYN packet, it ignores the packet
                if syn_packet[PACKET_FLAG_INDEX] == SOCK352_SYN:
                    got_connection_request = True
            # if the receive times out while receiving a SYN packet, it tries to listen again
            except syssock.timeout:
                pass

        # Step 2: Send a SYN/ACK packet for the 3-way handshake
        # creates the flags bit to be the bit-wise OR of SYN/ACK
        flags = SOCK352_SYN | SOCK352_ACK
        # creates the SYN/ACK packet to ACK the connection request from client
        # and sends the SYN to establish the connection from this end
        syn_ack_packet = self.createPacket(flags=flags,
                                           sequence_no=self.sequence_no,
                                           ack_no=syn_packet[PACKET_SEQUENCE_NO_INDEX] + 1)
        # increments the sequence number as it just consumed it when creating the SYN/ACK packet
        self.sequence_no += 1
        # sends the created packet to the address from which it received the SYN packet
        self.socket.sendto(syn_ack_packet, addr)

        # Receive the final ACK to complete the handshake and establish connection
        got_final_ack = False
        while not got_final_ack:
            try:
                # keeps trying to receive the final ACK packet to finalize the connection
                (ack_packet, addr) = self.socket.recvfrom(PACKET_HEADER_LENGTH)
                ack_packet = struct.unpack(PACKET_HEADER_FORMAT, ack_packet)
                # if the unpacked packet has the ACK flag set, we are done
                if ack_packet[PACKET_FLAG_INDEX] == SOCK352_ACK:
                    got_final_ack = True
            # if the server times out when trying to receive the final ACK, it retransmits the SYN/ACK packet
            except syssock.timeout:
                self.socket.sendto(syn_ack_packet, addr)

        # updates the server's ack number to be the last packet's sequence number + 1
        self.ack_no = ack_packet[PACKET_SEQUENCE_NO_INDEX] + 1

        # updates the server's send address
        self.send_address = (addr[0], portTx)

        # connect to the client using the send address just set
        # self.socket.connect(self.send_address)

        # updates the connected boolean to reflect that the server is now connected
        self.is_connected = True

        print("Server is now connected to the client at %s:%s" % (self.send_address[0], self.send_address[1]))

        if len(args) >= 1:
            if args[0] == ENCRYPT:
                self.encrypt = True
                if (addr[0], str(portTx)) in privateKeys:
                    secret_key = privateKeys[(addr[0], str(portTx))]
                else:
                    print 'not find private key in accept()'
                    return 0, 0

                if (addr[0], str(portRx)) in publicKeys:
                    public_key = publicKeys[(addr[0], str(portRx))]
                else:
                    print 'not find public key in accept()'
                    return 0, 0

                server_box = Box(secret_key, public_key)

        # your code goes here 

        return self, addr
    def close(self):
        # your code goes here 
        return 

    def send(self,buffer):
        # your code goes here 
        return 

    def recv(self,nbytes):
        # your code goes here
        return 



    


