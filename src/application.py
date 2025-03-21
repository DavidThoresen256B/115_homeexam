# Imported libraries
import argparse
import struct
import socket
import os
import time
from datetime import datetime


# Global variables
HEADER_FORMAT = "HHH"
HEADER_SIZE = 6
FLAGS_SYN = 0x1
FLAGS_ACK = 0x2
FLAGS_FIN = 0x4
DATA_SIZE = 994
MAX_PACKET_SIZE = 1000


# Function to be called when run directly in command-line
def main():
    """
    Description
        This function parses custom arguments from command-line, then calls other functions based on evocation and handles exceptions
    Arguments
        This function has no arguments because it do not need them
    Returnes
        This function has no value to return because it is the scripts entry point for the program
    """

    # Optional arguments
    parser = argparse.ArgumentParser(description="reliable file transport protocol over UDP")
    parser.add_argument("-s", "--server", action="store_true", help="enable server mode")
    parser.add_argument("-c", "--client", action="store_true", help="enable client mode")
    parser.add_argument("-i", "--ip", type=str, default="127.0.0.1", help="IP address for server, must be in dotted decimal format 10.0.1.2, default: 127.0.0.1")
    parser.add_argument("-p", "--port", type=int, default=8088, help="port number for server, must be an integer in the range [1024, 65535], default: 8088")
    parser.add_argument("-f", "--file", type=str, help="jpg file to transfer")
    parser.add_argument("-w", "--window", type=int, default=3, help="sliding window size, default: 3")
    parser.add_argument("-d", "--discard", type=int, help="a custom test case to skip a sequence number to check for retransmission")

    # Parse command-line arguments and store them in args
    args = parser.parse_args()

    # If server flag is envoked, then call receiveFile()
    if args.server:
        receiveFile(args.ip, args.port, args.discard)

    # If client flag is envoked, then continue
    elif args.client:

        # If file flag is envoked, then call sendFile()
        if args.file:
            sendFile(args.file, args.ip, args.port, args.window)

        # If file flag is not envoked, then print error message
        else:
            print("Please specify file to transmit")

    # If no server or client flag is envoked, then print error message
    else:
        print("Please specify either server (-s) or client (-c) mode")


# Function for creating a packet
def createPacket(seq_num, ack_num, flags, data=b""):
    """
    Description
        This function creates a packet with the header and data.
    Arguments
        seq_num: An integer holding the sequence number for the packet
        ack_num: An integer holding the acknowledgment number for the packet
        flags: An integer holding the flags for the packet
        data: A byte sequence holding the data for the packet
    Returnes
        This function returns a byte sequence representing the packet with header and data,
        because the struct module packs into binary format suitable for transmission
    """

    # Pack into header using HEADER_FORMAT, then return packet
    header = struct.pack(HEADER_FORMAT, seq_num, ack_num, flags)
    return header + data


# Function for parsing a packet
def parsePacket(packet):
    """
    Description
        This function parses a packet to extract its header and data
    Arguments
        packet: A byte sequence holding the packet with header and data
    Returnes
        This function returns a tuple containing the seq_num, ack_num, flags, and data,
        because it slices the packet to seperate header and data,
        then unpacks header from binary format into indivudal fields
    """

    # Extract header and data by slicing packet using HEADER_SIZE from packet end and start
    header = packet[:HEADER_SIZE]
    data = packet[HEADER_SIZE:]

    # Unpack header fields from header, then return packet
    seq_num, ack_num, flags = struct.unpack(HEADER_FORMAT, header)
    return seq_num, ack_num, flags, data


# Function for creating a SYN packet
def createSynPacket(seq_num, ack_num, flags, file_size):
    """
    Description
        This function creates a SYN packet with the header and file size.
    Arguments
        seq_num: An integer holding the sequence number for the packet
        ack_num: An integer holding the acknowledgment number for the packet
        flags: An integer holding the flags for the packet
        file_size: An integer holding the size of the file to be transferred
    Returnes
        This function returns a byte sequence representing the SYN packet with header and file size,
        because the struct module packs into binary format suitable for transmission
    """

    # Pack into header using HEADER_FORMAT
    header = struct.pack(HEADER_FORMAT, seq_num, ack_num, flags)

    # Pack file_size into binary format, then return SYN packet
    file_size_data = struct.pack("I", file_size)
    return header + file_size_data


# Function for parsing a SYN packet
def parseSynPacket(packet):
    """
    Description
        This function parses a SYN packet to extract its header and file size and handle exception
    Arguments
        packet: A byte sequence holding the packet with header and file size
    Returnes
        This function returns a tuple containing the seq_num, ack_num, flags, and file size,
        because it slices the packet to seperate header and file size,
        then unpacks header and file size from binary format into indivudal fields
    """

    # Extract header and file_size_data using HEADER_SIZE
    header = packet[:HEADER_SIZE]
    file_size_data = packet[HEADER_SIZE : HEADER_SIZE + 4]

    # Unpack header fields from header
    seq_num, ack_num, flags = struct.unpack(HEADER_FORMAT, header)

    # If file_size_data is less than 4, then print message
    if len(file_size_data) < 4:
        raise ValueError("Incomplete file size data received")

    # Unpack file_size_data into binary format, then return parsed SYN packet
    (file_size,) = struct.unpack("I", file_size_data)
    return seq_num, ack_num, flags, file_size


# Function for sending packets
def sendPacket(seq_num, window, file, sock, retransmit, server_address):
    """
    Description
        This function manages the sliding window, controls packet delivery,
        handles packet resending and sends a packet of data from file to server
    Arguments
        seq_num: An integer holding the sequence number for the packet
        window: A list holding the sequence numbers within the packets window
        file: A file which data is read and sent to the packet
        sock: A socket used to send the packet
        retransmit: A boolean holding the discard state
        server_address: A tuple holding the IP address and port to the server
    Returnes
        This function returns a boolean representing whether data and packet operations was successful,
        because this value is further used in packet operations
    """

    # If seq_num is not in window, seek correct position in file, then read file
    if seq_num not in window:
        file.seek(DATA_SIZE * (seq_num - 1))
        data = file.read(DATA_SIZE)

        # If no more data to read from file, return false, then add the sequence number to window to track sent packets
        if not data:
            return False
        window.append(seq_num)

    # If seq_num is in window, seek correct position in file, then read file
    else:
        file.seek(DATA_SIZE * (seq_num - 1))
        data = file.read(DATA_SIZE)

    # Update current time, then format to string using millisecond
    current_time = datetime.now()
    format_time = (f"{current_time.strftime('%H:%M:%S')}.{current_time.microsecond // 1000:03d}")

    # Create ACK packet and send to server
    packet = createPacket(seq_num, 0, 0, data=data)
    sock.sendto(packet, server_address)

    # If retransmit is true, then print message
    if retransmit:
        print(f"{format_time} -- retransmitting packet with seq = {seq_num}")

    # If retransmit is false, convert window to string format, print message, then return true
    else:
        window_string = "{" + ", ".join(map(str, window)) + "}"
        print(f"{format_time} -- packet with seq = {seq_num} is sent, sliding window = {window_string}")
    return True


# Function for sending a file (client)
def sendFile(filename, server_ip, server_port, window_size):
    """
    Description
        This function sets up a file transfer system over UDP. 
        It establishes a connection, handles data transmission using sliding window, 
        then starts the connection teardown. 
        It uses timeouts and retransmissions to handle packet loss.
    Arguments
        filename: A string holding the name of the file to transfer
        server_ip: A string holding the IP address of the server
        server_port: An integer holding the port of the server
        window_size: An integer holding the sliding window size
    Returnes
        This function has no value to return because it performs the file transfer operations,
        and produces no value
    """

    # Create UDP socket, then bind to IP adress and port (alias: sock)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:

        # Set timeout and server_address
        sock.settimeout(0.5)
        server_address = (server_ip, server_port)

        # Find filesize to be sent and create SYN packet and send to server, then print message
        filesize = os.path.getsize(filename)
        syn_packet = createSynPacket(0, 0, FLAGS_SYN, filesize)
        sock.sendto(syn_packet, server_address)
        print("\nConnection Establisht Phase:\n\nSYN packet is sent")

        # Loop to wait for SYN-ACK packet
        while True:

            # Attempt to receive data from socket, then parse it
            try:
                response, _ = sock.recvfrom(MAX_PACKET_SIZE)
                seq_num, ack_num, flags, file_size = parseSynPacket(response)

                # If received packet has SYN-ACK flag set, print message, then exit
                if flags & FLAGS_SYN and flags & FLAGS_ACK:
                    print("SYN-ACK packet is received")
                    break

            # If timeout occurs, resend SYN packet to server, then print message
            except socket.timeout:
                sock.sendto(syn_packet, server_address)
                print("Resending SYN packet")

            # If connection error occurs, print message, then return
            except ConnectionResetError:
                print("\nConnection failed")
                return

            # If socket error occurs, print message, then return (alias: e)
            except socket.error as e:
                print(f"\nConnection failed: Socket error occurred - {str(e)}")
                return

        # Create ACK packet and send to server, then print message
        ack_packet = createPacket(1, seq_num + 1, FLAGS_ACK)
        sock.sendto(ack_packet, server_address)
        print("ACK packet is sent\nConnection established\n\nData Transfer:\n")

        # Open filename in binary read mode (alias: file)
        with open(filename, "rb") as file:

            # Set seq_num to 1, create list to store packets,
            # create dictionary to store unacknowledged packets, then set retransmit to false
            seq_num = 1
            window = []
            unack_packets = {}
            retransmit = False

            # Loop to manage sliding window and retransmissions
            while True:

                # If window length is less than window_size call sendPacket()
                while len(window) < window_size:
                    if sendPacket(seq_num, window, file, sock, retransmit, server_address):

                        # Update packet send time, then increase seq_num by 1
                        unack_packets[seq_num] = datetime.now()
                        seq_num += 1

                    # If window length is not less than window_size, then exit
                    else:
                        break

                # If no more data to send, print message, then exit
                if not window:
                    print("DATA Finished")
                    break

                # Attempt to receive incoming ACKs and send more data as window slides
                try:
                    response, _ = sock.recvfrom(MAX_PACKET_SIZE)
                    _, ack_num, flags, _ = parsePacket(response)

                    # If received packet has ACK flag set
                    if flags & FLAGS_ACK:

                        # Update current time, then format to string using millisecond, then print message
                        current_time = datetime.now()
                        format_time = f"{current_time.strftime('%H:%M:%S')}.{current_time.microsecond // 1000:03d}"
                        print(f"{format_time} -- ACK for packet = {ack_num} is received")

                        # New list and dictionary to hold filtered sequence numbers and unacknowledged packets
                        filtered_window = []
                        filtered_unack_packets = {}

                        # Loop through each sequence number in window
                        for seq in window:

                            # If the sequence number is larger than the ack_num, then keep it
                            if seq > ack_num:
                                filtered_window.append(seq)

                        # Loop through each sequence number and timestamp pair in unack_packets
                        for seq, ts in unack_packets.items():

                            # If sequence number is larger than the ack_num, then keep it
                            if seq > ack_num:
                                filtered_unack_packets[seq] = ts

                        # Reassign window and unack_packets to filtered filtered_window and filtered_unack_packets
                        window = filtered_window
                        unack_packets = filtered_unack_packets

                        # If window length is less than window_size call sendPacket()
                        while len(window) < window_size:
                            if sendPacket(seq_num, window, file, sock, retransmit, server_address):

                                # Update packet send time, then increase seq_num by 1
                                unack_packets[seq_num] = datetime.now()
                                seq_num += 1

                            # If window length is not less than window_size, then exit
                            else:
                                break

                # If timout occurs, retransmit unacknowledged packets
                except socket.timeout:

                    # Update current time, then format to string using millisecond, then print message
                    current_time = datetime.now()
                    format_time = f"{current_time.strftime('%H:%M:%S')}.{current_time.microsecond // 1000:03d}"
                    print(f"{format_time} -- RTO occurred")

                    # Loop through window snapshot
                    for seq in window:

                        # Set retransmit to True, call sendPacket(), then update packet send time
                        retransmit = True
                        sendPacket(seq, window, file, sock, retransmit, server_address)
                        unack_packets[seq] = datetime.now()

                    # Set retransmit to false
                    retransmit = False

        # Create FIN packet and send to server, then print message
        fin_packet = createPacket(seq_num, 0, FLAGS_FIN)
        sock.sendto(fin_packet, server_address)
        print("\n\nConnection Teardown:\n\nFIN packet is sent")

        # Loop to wait for FIN-ACK packet
        while True:

            # Attempt to receive data from socket, then parse it
            try:
                response, _ = sock.recvfrom(MAX_PACKET_SIZE)
                seq_num, ack_num, flags, data = parsePacket(response)

                # If received packet has FIN-ACK flag set, print message, then exit
                if flags & FLAGS_FIN and flags & FLAGS_ACK:
                    print("FIN-ACK packet is received")
                    break

            # If timout occurs, resend FIN packet to server, then print message
            except socket.timeout:
                sock.sendto(fin_packet, server_address)
        print("Connection Closes\n")


# Function for receiving a file (server)
def receiveFile(ip, port, discard=None):
    """
    Description
        This function sets up a UDP server on an IP address and port, 
        then handles the process of receiving a file transmitted over network. 
        It calculates the throughput of received data and can optionally 
        discard packets with a specified sequence number to simulate packet loss.
    Arguments
        ip: A string holding the IP address of the server
        port: An integer holding the port of the server
        discard: An integer holding the sequence number to skip
    Returnes
        This function has no value to return because it sets up the UDP server to receive a file,
        and produces no value
    """

    # Create UDP socket and bind to IP adress and port (alias: sock)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:

        # Bind socket to address
        sock.bind((ip, port))

        # Loop to wait for SYN packet
        while True:

            # Receive data from socket, then parse it
            data, client_address = sock.recvfrom(MAX_PACKET_SIZE)
            seq_num, ack_num, flags, file_size = parseSynPacket(data)

            # If received packet has SYN flag set, then print message
            if flags & FLAGS_SYN:
                print("\nSYN packet is received")

                # Create SYN-ACK packet and send to client, print message, then exit
                syn_ack_packet = createSynPacket(seq_num + 1, 0, FLAGS_SYN | FLAGS_ACK, file_size)
                sock.sendto(syn_ack_packet, client_address)
                print("SYN-ACK packet is sent")
                break

        # Loop to wait for ACK packet
        while True:

            # Receive data from socket, then parse it
            data, _ = sock.recvfrom(MAX_PACKET_SIZE)
            seq_num, ack_num, flags, data = parsePacket(data)

            # If received packet has ACK flag set, print message, then exit
            if flags & FLAGS_ACK:
                print("ACK packet is received")
                break

        # Print message
        print("Connection established")

        # Set expected_seq_num to 1, create dictionary to store received data, then record start time
        expected_seq_num = 1
        received_data = {}
        start_time = time.time()

        # Loop to receive packets from socket connection
        while True:

            # Update current time, then format to string using millisecond
            current_time = datetime.now()
            format_time = f"{current_time.strftime('%H:%M:%S')}.{current_time.microsecond // 1000:03d}"

            # Attempt to receive data from socket, then parse it
            try:
                data, _ = sock.recvfrom(MAX_PACKET_SIZE)
                seq_num, ack_num, flags, data = parsePacket(data)

                # If seq_num equals discard number
                if seq_num == discard:

                    # Set discard to none to only discard one packet, then skip
                    discard = None
                    continue

                # If seq_num is equal to expected_seq_num, then print message
                if seq_num == expected_seq_num:
                    print(f"{format_time} -- packet {seq_num} is received")

                    # Create ACK packet and send to client, then print message
                    ack_packet = createPacket(0, seq_num, FLAGS_ACK)
                    sock.sendto(ack_packet, client_address)
                    print(f"{format_time} -- sending ack for the received {seq_num}")

                    # Update seq_num for next packet
                    expected_seq_num += 1
                    received_data[seq_num] = data

                # If seq_num is not equal to expected_seq_num, then print message
                else:
                    print(f"{format_time} -- out-of-order packet {seq_num} is received")

            # If timeout occurs, then print message
            except socket.timeout:
                print(f"{format_time} -- RTO occurred")

            # If received packet has FIN flag set, then print message
            if flags & FLAGS_FIN:
                print("\nFIN packet is received")

                # Create FIN-ACK packet and send to client, print message, then exit
                fin_ack_packet = createPacket(seq_num + 1, 0, FLAGS_ACK | FLAGS_FIN)
                sock.sendto(fin_ack_packet, client_address)
                print("FIN-ACK packet is sent")
                break

        # Open received_file in binary write mode (alias: file)
        with open("received_file", "wb") as file:

            # Loop through received_data, then write all received_data to received_file
            for seq in sorted(received_data):
                file.write(received_data[seq])

        # End session time, then calculate total time
        end_time = time.time()
        total_time = end_time - start_time

        # Calculate total number of bytes by looping through received_data and sum them
        total_bytes = sum(len(data) for data in received_data.values())

        # Calculate throughput, then print message
        throughput = (total_bytes * 8 / 1000 / 1000) / total_time
        print(f"\nThe throughput is {throughput:.2f} Mbps\nConnection Closes\n")


# Ensure code only runs when called directly in command-line
if __name__ == "__main__":
    main()
