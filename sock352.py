
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
ENCRYPT_SIZE = 40
# String message to print out that a connection has been already established
CONNECTION_ALREADY_ESTABLISHED_MESSAGE = "This socket supports a maximum of one connection\n" \
                                 "And a connection is already established"

# Box
server_box = None
client_box = None
client_nonce = None

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
    
    if filename:
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
        self.total_size = 0
        # the corresponding lock for the retransmit boolean
        self.retransmit_lock = threading.Lock()
        # declares the last packet that was acked (for the sender only)
        self.last_data_packet_acked = None
        
    def bind(self, address):
        self.socket.bind((address[0], portRx))

    def connect(self, *args):

        global portTx,portRx, client_box, client_nonce
        global ENCRYPT

        # example code to parse an argument list (use option arguments if you want)  
        if len(args) >= 1:
            self.send_address = (args[0][0], portTx)
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

            print '---- first handshake sent'

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

            print '---- second handshake receive'

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
            print ("---- third hand shake sent, Client is now connected to the server at %s:%s" % (self.send_address[0], self.send_address[1]))

            if len(args) >= 2:
                if args[1] == ENCRYPT:
                    self.encrypt = True

                    if (args[0][0], str(portTx)) not in privateKeys or (args[0][0], str(portRx)) not in publicKeys:
                        print("---- Key not found")
                        return
                    else:
                        clientSk = privateKeys[(args[0][0], str(portTx))]
                        serverPk = publicKeys[(args[0][0], str(portRx))]
                        client_box = Box(clientSk, serverPk)
                        client_nonce = nacl.utils.random(Box.NONCE_SIZE)

    def listen(self,backlog):
        # listen is not used in this assignments 
        pass

    def accept(self,*args):
        # example code to parse an argument list (use option arguments if you want)
        global ENCRYPT, server_box, MAXIMUM_PAYLOAD_SIZE

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

        print '---- first handshake received'

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
        print '---- second handshake sent'

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

        print '---- third handshake received'
        # updates the server's ack number to be the last packet's sequence number + 1
        self.ack_no = ack_packet[PACKET_SEQUENCE_NO_INDEX] + 1

        # updates the server's send address
        self.send_address = (addr[0], portTx)

        # connect to the client using the send address just set
        # self.socket.connect(self.send_address)

        # updates the connected boolean to reflect that the server is now connected
        self.is_connected = True

        print("---- Server is now connected to the client at %s:%s" % (self.send_address[0], self.send_address[1]))

        if len(args) >= 1:
            if args[0] == ENCRYPT:
                self.encrypt = True
                MAXIMUM_PAYLOAD_SIZE -= ENCRYPT_SIZE
                if addr[0] == '127.0.0.1':
                    tempAddr = 'localhost'
                else:
                    tempAddr = addr[0]

                if (tempAddr, str(portRx)) in privateKeys:
                    secret_key = privateKeys[(tempAddr, str(portRx))]
                else:
                    print privateKeysHex
                    print '---- not find private key in accept()'
                    return self, 0

                if (tempAddr, str(portTx)) in publicKeys:
                    public_key = publicKeys[(tempAddr, str(portTx))]
                else:
                    print '---- not find public key in accept()'
                    return self, 0

                server_box = Box(secret_key, public_key)

        return self, addr

    def close(self):
        # makes sure there is a connection established in the first place before trying to close it
        if not self.is_connected:
            print ("No connection is currently established that can be closed")
            return

        # checks if the server can close the connection (it can close only when it has received the last packet/ack)
        if self.can_close:
            # calls the socket's close method to finally close the connection
            self.socket.close()
            # resets all the appropriate variables
            self.send_address = None
            self.is_connected = False
            self.can_close = False
            self.sequence_no = randint(1, 100000)
            self.ack_no = 0
            self.data_packets = []
            self.file_len = -1
            self.retransmit = False
            self.last_data_packet_acked = None
        # in the case that it cannot close, it prints out that it's still waiting for data
        else:
            print "Failed to close the connection!\n" \
                  "Still waiting for data transmission/reception to finish"

    def send(self, buffer):
        # makes sure that the file length is set and has been communicated to the receiver
        if self.file_len == -1:
            self.socket.sendto(buffer, self.send_address)
            self.file_len = struct.unpack("!L", buffer)[0]
            print ("File length sent: " + str(self.file_len) + " bytes")
            return self.file_len

        # sets the starting sequence number and creates data packets starting from this number
        start_sequence_no = self.sequence_no
        total_packets = self.create_data_packets(buffer)
        print '---- numer of packages: %d' % total_packets
        # creates another thread that is responsible for receiving acks for the data packets sent
        recv_ack_thread = threading.Thread(target=self.recv_acks, args=())
        recv_ack_thread.setDaemon(True)
        recv_ack_thread.start()

        # starts the data packet transmission
        print ("Started data packet transmission...")
        while not self.can_close:
            # calculates the index from which to start sending packets
            # when sending the first time, it will be 0
            # otherwise, when retransmitting, it will calculate the Go-Back-N based
            # on the last data packet that was acked
            if self.last_data_packet_acked is None:
                resend_start_index = 0
            else:
                resend_start_index = int(self.last_data_packet_acked[PACKET_ACK_NO_INDEX]) - start_sequence_no

            # checks if the packet to start retransmitting from is the total amount of packets this
            # would mean the last data packet has been transmitted and so its safe to close the connection
            if resend_start_index == total_packets:
                self.can_close = True

            # adjusts retransmit to indicate that the sender started retransmitting using locks
            self.retransmit_lock.acquire()
            self.retransmit = False
            self.retransmit_lock.release()

            # continually tries to transmit packets while the connection cannot be closed from resend start index
            # to the rest of the packets (or at least until as much as it can)
            while not self.can_close and resend_start_index < total_packets and not self.retransmit:

                # tries to send the packet and catches any connection refused exception which might mean
                # the connection was unexpectedly closed/broken
                try:
                    self.socket.sendto(self.data_packets[resend_start_index], self.send_address)
                    print '---- %d bytes sent, package %d' % (len(self.data_packets[resend_start_index]), resend_start_index)

                # print 'sent %d in send()' % sys.getsizeof(self.data_packets[resend_start_index])
                # Catch error 111 (Connection refused) in the case where the last ack
                # was received by this sender and thus the connection was closed
                # by the receiver but it happened between this sender's checking
                # of that connection close condition
                except syssock.error, error:
                    if error.errno != 111:
                        raise error
                    self.can_close = True
                    break
                resend_start_index += 1

        # waits for recv thread to finish before returning from the method
        recv_ack_thread.join()

        print ("Finished transmitting data packets")
        return len(buffer)

    def recv(self, nbytes):
        # if the file length has not been set, receive the file length from the sender
        if self.file_len == -1:
            file_size_packet = self.socket.recv(struct.calcsize("!L"))
            self.file_len = struct.unpack("!L", file_size_packet)[0]
            print ("File Length Received: " + str(self.file_len) + " bytes")
            return file_size_packet

        # sets the bytes to receive to be how many bytes it expects
        bytes_to_receive = nbytes

        # also declares a variable to hold all the string of the data that has been received
        data_received = ""

        print ("Started receiving data packets...")
        # keep trying to receive packets until the receiver has more bytes left to receive
        while bytes_to_receive > 0:
            # tries to receive the packet
            try:
                # receives the packet of header + maximum data size bytes (although it will be limited
                # by the sender on the other side)
                print '%d bytes left to receive' % (bytes_to_receive + PACKET_HEADER_LENGTH)
                if self.encrypt:
                    packet_received = self.socket.recv(PACKET_HEADER_LENGTH + bytes_to_receive + ENCRYPT_SIZE + 100000)
                else:
                    packet_received = self.socket.recv(PACKET_HEADER_LENGTH + bytes_to_receive)
                print '%d bytes received' % len(packet_received)

                # sends the packet to another method to manage it and gets back the data in return
                str_received = self.manage_recvd_data_packet(packet_received)

                # adjusts the numbers accordingly based on return value of manage data packet
                if str_received is not None:
                    # appends the data received to the total buffer of all the data received so far
                    data_received += str_received
                    # decrements bytes to receive by the length of last data received since that many
                    # less bytes need to be transmitted now
                    bytes_to_receive -= len(str_received)

            # catches timeout, in which case it just tries to another packet
            except syssock.timeout:
                pass

        # since it's done with receiving all the bytes, it marks the socket as safe to close
        self.can_close = True

        print ("Finished receiving the data")
        # returns the data received
        return data_received

    # creates a generic packet to be sent using parameters that are
    # relevant to Part 1. The default values are specified above in case one or more parameters are not used
    def createPacket(self, flags=0x0, sequence_no=0x0, ack_no=0x0, payload_len=0x0, opt_ptr=0x0):
        if self.encrypt:
            opt_ptr = 0x1

        print '---- flag opt_ptr: %d' % opt_ptr
        return struct.Struct(PACKET_HEADER_FORMAT).pack \
            (
                0x1,  # version
                flags,  # flags
                opt_ptr,  # opt_ptr
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

    # method responsible for breaking apart the buffer into chunks of maximum payload length
    def create_data_packets(self, buffer):
        global client_box, client_nonce
        # calculates the total packets needed to transmit the entire buffer
        total_packets = len(buffer) / MAXIMUM_PAYLOAD_SIZE

        # if the length of the buffer is not divisible by the maximum payload size,
        # that means an extra packet will need to be sent to transmit the left over data
        # so it increments total packets by 1
        if len(buffer) % MAXIMUM_PAYLOAD_SIZE != 0:
            total_packets += 1

        # sets the payload length to be the maximum payload size
        payload_len = MAXIMUM_PAYLOAD_SIZE

        # iterates up to total packets and creates each packet
        for i in range(0, total_packets):
            # if we are about to construct the last packet, checks if the payload length
            # needs to adjust to reflect the left over size or the entire maximum packet size

            if i == total_packets - 1:
                if len(buffer) % MAXIMUM_PAYLOAD_SIZE != 0:
                    payload_len = len(buffer) % MAXIMUM_PAYLOAD_SIZE
                    print '----- last package size: %d' % payload_len

            # creates the new packet with the appropriate header
            new_packet = self.createPacket(flags=0x0,
                                           sequence_no=self.sequence_no,
                                           ack_no=self.ack_no,
                                           payload_len=payload_len)
            # consume the sequence and ack no as it was used to create the packet
            self.sequence_no += 1
            self.ack_no += 1

            message = buffer[MAXIMUM_PAYLOAD_SIZE * i: MAXIMUM_PAYLOAD_SIZE * i + payload_len]
            if self.encrypt:
                message = client_box.encrypt(message, client_nonce)

            # attaches the payload length of buffer to the end of the header to finish constructing the packet
            self.data_packets.append(new_packet + message)
        return total_packets

    # method responsible for receiving acks for the data packets the sender sends
    def recv_acks(self):
        # tries to receive the ack as long as the connection has is not ready to be closed
        # this can only happen when the sender receives a Connection refused error
        while not self.can_close:
            # tries to receive the new packet and un-pack it
            try:
                new_packet = self.socket.recv(PACKET_HEADER_LENGTH)
                new_packet = struct.unpack(PACKET_HEADER_FORMAT, new_packet)

                # ignores the packet if the ACK flag is not set.
                if new_packet[PACKET_FLAG_INDEX] != SOCK352_ACK:
                    continue

                # if the last data packet acked is not set, the newly received packet is set to be the last data packet
                # acked. Otherwise, checks if the new packet's sequence number is greater than the last data packet
                # acked's sequence number, otherwise it assumes it could be a duplicate ACK
                if self.last_data_packet_acked is None or\
                        new_packet[PACKET_SEQUENCE_NO_INDEX] > self.last_data_packet_acked[PACKET_SEQUENCE_NO_INDEX]:
                    self.last_data_packet_acked = new_packet

            # in the case where the recv times out, it locks down retransmit and sets it to True
            # to indicate that no ACk was received within the timeout window of 0.2 seconds
            except syssock.timeout:
                self.retransmit_lock.acquire()
                self.retransmit = True
                self.retransmit_lock.release()

            # Catch error 111 (Connection refused) in the case where the sender is
            # anticipating an ACK for a packet it sent out, which hasn't timed out
            # but the server has closed the connection since it finished receiving
            # the data and an ACK is already on its way to this sender
            except syssock.error, error:
                if error.errno != 111:
                    raise error
                self.can_close = True
                return

    # Manages a packet received based on the flag
    def manage_recvd_data_packet(self, packet):
        packet_header = packet[:PACKET_HEADER_LENGTH]
        packet_data = packet[PACKET_HEADER_LENGTH:]
        packet_header = struct.unpack(PACKET_HEADER_FORMAT, packet_header)
        packet_header_flag = packet_header[PACKET_FLAG_INDEX]

        # Check if the packet that was received has the expected sequence no
        # for the next in-order sequence no (which is the ack number)
        #     Case 1, the sequence number is in-order so send back the acknowledgement
        #     Case 2, the sequence number is out-of-order so drop the packet
        if packet_header[PACKET_SEQUENCE_NO_INDEX] != self.ack_no:
            return

        message = server_box.decrypt(packet_data)
        # adds the payload data to the data packet array
        self.data_packets.append(message)
        # increments the acknowledgement by 1 since it is supposed to be the next expected sequence number
        self.ack_no += 1
        # finally, it creates the ACK packet using the server's current sequence and ack numbers
        ack_packet = self.createPacket(flags=SOCK352_ACK,
                                       sequence_no=self.sequence_no,
                                       ack_no=self.ack_no)
        # the sequence number is incremented since it was consumed upon packet creation
        self.sequence_no += 1
        # the server sends the packet to ACK the data packet it received
        self.socket.sendto(ack_packet, self.send_address)

        # the data or the payload is then itself is returned from this method
        return message
