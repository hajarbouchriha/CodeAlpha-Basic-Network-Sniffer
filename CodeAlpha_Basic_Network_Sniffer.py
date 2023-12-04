# -*- coding: utf-8 -*-
"""
Created on Fri Nov 17 18:20:59 2023

@author: bouch
"""

import socket
import struct

# Define indentation strings for formatting
TAB_1 = "\t - "
TAB_2 = "\t\t - "
TAB_3 = "\t\t\t - "
TAB_4 = "\t\t\t\t - "
DATA_TAB_1 = "\t "
DATA_TAB_2 = "\t\t "
DATA_TAB_3 = "\t\t\t "
DATA_TAB_4 = "\t\t\t\t "

def capture_traffic():
    # Create a raw socket for capturing network traffic
    #socket.ntohs(3) is for making sure that the byte order is correct so we can read it 
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    #This loop for listening for any data that come across
    while True:
        # Receive raw data and address information
        #The recvfrom method in the socket module helps us to receive all the data (0 and 1) from the socket and store it in raw_data and addr variables 
        #The parameter passed is the buffer size; 65565 is the maximum buffer size  
        raw_data, address = connection.recvfrom(65536)

        # Analyze Ethernet frame
        dest_address, source_address, eth_protocol, packet_data = analyze_ethernet_frame(raw_data)
        print("\nEthernet Frame:")
        print(TAB_1 + f"Destination Address: {dest_address}, Source Address: {source_address}, Protocol: {eth_protocol}")
        
        #Value of 8 for IPv4
        if eth_protocol == 8:
            # Analyze IPv4 packet
            (version, header_length, ttl, protocol, src_ip, dest_ip, packet_data) = analyze_ipv4_packet(packet_data)
            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + f'Version: {version}, Header Length: {header_length}, TTL: {ttl}')
            print(TAB_2 + f'Protocol: {protocol}, Source IP: {src_ip}, Destination IP: {dest_ip}')

            if protocol == 1:
                # Analyze ICMP packet
                icmp_type, code, checksum, packet_data = analyze_icmp_packet(packet_data)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + f'Type: {icmp_type}, Code: {code}, Checksum: {checksum}')
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, packet_data))

            elif protocol == 6:
                # Analyze TCP segment
                src_port, dest_port, sequence, acknowledgement, urg, ack, psh, rst, syn, fin, packet_data = analyze_tcp_segment(packet_data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + f'Source Port: {src_port}, Destination Port: {dest_port}')
                print(TAB_2 + f'Sequence: {sequence}, Acknowledgement: {acknowledgement}')
                print(TAB_2 + "Flags:")
                print(TAB_3 + f'URG: {urg}, ACK: {ack}, PSH: {psh}, RST: {rst}, SYN: {syn}, FIN: {fin}')
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, packet_data))

            elif protocol == 17:
                # Analyze UDP segment
                src_port, dest_port, length, packet_data = analyze_udp_packet(packet_data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + f'Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}')
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, packet_data))

            else:
                print(TAB_1 + 'Data:')
                print(format_multi_line(DATA_TAB_2, packet_data))

        else:
            print('Data:')
            print(format_multi_line(DATA_TAB_1, packet_data))


def analyze_ethernet_frame(data):
    # Unpack Ethernet frame data
    dest_address, source_address, protocol = struct.unpack('! 6s 6s H', data[:14])
    return get_address(dest_address), get_address(source_address), socket.htons(protocol), data[14:]


def get_address(bytes_address):
    # Format MAC address
    formatted_address = ':'.join(map('{:02x}'.format, bytes_address)).upper()
    return formatted_address


def analyze_ipv4_packet(data):
    try:
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        ttl, protocol, source_ip, dest_ip = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        return version, header_length, ttl, protocol, format_ip_address(source_ip), format_ip_address(dest_ip), data[header_length:]
    except Exception as e:
        print(f"Error analyzing IPv4 packet: {e}")
        return None

def format_ip_address(address):
    # Format IPv4 address
    formatted_address = '.'.join(map(str, address))
    return formatted_address


def analyze_icmp_packet(data):
    # Analyze ICMP packet
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


def analyze_tcp_segment(data):
    # Analyze TCP segment
    src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4 #offset is the header length of the TCP segment
    urg = (offset_reserved_flags & 32) >> 5
    ack = (offset_reserved_flags & 16) >> 4
    psh = (offset_reserved_flags & 8) >> 3
    rst = (offset_reserved_flags & 4) >> 2
    syn = (offset_reserved_flags & 2) >> 1
    fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, urg, ack, psh, rst, syn, fin, data[offset:]


def analyze_udp_packet(data):
    # Analyze UDP packet
    src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, length, data[8:]


def format_multi_line(prefix, string, size=20):
    # Format multiline data for display
    if isinstance(string, bytes):
        lines = []
        for i in range(0, len(string), size):
            chunk = string[i:i + size]
            hex_part = ' '.join(f'{byte:02x}' for byte in chunk)
            text_part = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in chunk)
            lines.append(f"{prefix} {hex_part.ljust(size * 3)}  {text_part}")
        return '\n'.join(lines)
# The purpose of this function is to format byte data to mimic the output of a standard TCP stream, as seen in tools like Wireshark or Burp Suite.

# It presents the byte data in a structured and aligned format, showing both the hexadecimal and ASCII representations of the data.

# The size parameter provides flexibility by allowing you to control the length of each line, facilitating better readability and analysis.   

if __name__ == "__main__":
    # Start capturing network traffic
    capture_traffic()
