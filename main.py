import argparse

from scapy.all import sniff

def define_arguments():
    """
    Processes the user-defined filter (BFT Filters).
    :return: an ArgumentParser object, containing a field of user arguments that were passed in.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--count', help='The maximum number of packets to capture on the network. '
                                   'Defaults to 5 if not defined', type=int, default=5)
    parser.add_argument('-f', "--filter", type=str,  help='Defines the filter we would like to employ onto the packet '
                                                          'capturing process. By default, it is set to `tcp` for HTTP '
                                                          'traffic. An example filter can be: `tcp and/or port 80`', default='tcp')
    parser.add_argument('-t', "--timeout", type=int, help='Timeout (seconds) for the duration the packet capturing process '
                                                       'will continue before automatically stopping. Defaults to 10.'
                        , default=10)
    parser.add_argument('-i', "--interface", type=str, help='Used to monitor a specific network interface. Can be either of '
                                             'Ethernet or Wi-Fi.\n'
                                             'The naming for Ethernet may vary based on your Operating System --> \n'
                                             'Windows: `Ethernet`; macOS: `en0`; Linux: `eth0`, `eth1`. '
                                             'Defaults to Wi-Fi', default='Wi-Fi')
    args = parser.parse_args()
    return args


# Function to parse the Ethernet header
def parse_ethernet_header(hex_data):
    # Ethernet header is the first 14 bytes (28 hex characters)
    dest_mac = hex_data[0:12]
    source_mac = hex_data[12:24]
    ether_type = hex_data[24:28]

    # Convert hex MAC addresses to human-readable format
    dest_mac_readable = ':'.join(dest_mac[i:i + 2] for i in range(0, 12, 2))
    source_mac_readable = ':'.join(source_mac[i:i + 2] for i in range(0, 12, 2))

    print(f"Ethernet Header:\n"
          f"  Destination MAC: {dest_mac_readable}\n"
          f"  Source MAC: {source_mac_readable}\n"
          f"  EtherType: {ether_type}")
    return ether_type


# Function to parse ARP packet
def parse_arp_packet(hex_data):
    # ARP packet fields in hex
    hw_type = hex_data[28:32]
    proto_type = hex_data[32:36]
    hw_size = hex_data[36:38]
    proto_size = hex_data[38:40]
    opcode = hex_data[40:44]
    src_mac = hex_data[44:56]
    src_ip = hex_data[56:64]
    dst_mac = hex_data[64:76]
    dst_ip = hex_data[76:84]

    # Convert to human-readable formats
    src_mac_readable = ':'.join(src_mac[i:i + 2] for i in range(0, 12, 2))
    src_ip_readable = '.'.join(str(int(src_ip[i:i + 2], 16)) for i in range(0, 8, 2))
    dst_mac_readable = ':'.join(dst_mac[i:i + 2] for i in range(0, 12, 2))
    dst_ip_readable = '.'.join(str(int(dst_ip[i:i + 2], 16)) for i in range(0, 8, 2))

    print(f"ARP Packet:\n"
          f"  Hardware Type: {hw_type} (Dec: {int(hw_type, 16)})\n"
          f"  Protocol Type: {proto_type} (Dec: {int(proto_type, 16)})\n"
          f"  Hardware Size: {hw_size} (Dec: {int(hw_size, 16)})\n"
          f"  Protocol Size: {proto_size} (Dec: {int(proto_size, 16)})\n"
          f"  Opcode: {opcode} (Dec: {int(opcode, 16)})\n"
          f"  Sender MAC: {src_mac_readable}\n"
          f"  Sender IP: {src_ip_readable}\n"
          f"  Target MAC: {dst_mac_readable}\n"
          f"  Target IP: {dst_ip_readable}")


# Function to parse IPv4 packet
def parse_ipv4_packet(hex_data):
    version_ihl = hex_data[28:30]
    version = version_ihl[0]
    ihl = version_ihl[1]
    tos = hex_data[30:32]
    total_length = hex_data[32:36]
    identification = hex_data[36:40]
    flags_offset = hex_data[40:44]
    ttl = hex_data[44:46]
    protocol = hex_data[46:48]
    checksum = hex_data[48:52]
    src_ip = hex_data[52:60]
    dst_ip = hex_data[60:68]

    src_ip = '.'.join(str(int(src_ip[i:i + 2], 16)) for i in range(0, 8, 2))
    dst_ip = '.'.join(str(int(dst_ip[i:i + 2], 16)) for i in range(0, 8, 2))

    print(f"IPv4 Packet:\n"
          f"  Version: {version} (Dec: {int(version, 16)})\n"
          f"  IHL: {ihl} (Dec: {int(ihl, 16)} * 4 bytes)\n"
          f"  TOS: {tos} (Dec: {int(tos, 16)})\n"
          f"  Total Length: {total_length} (Dec: {int(total_length, 16)})\n"
          f"  Identification: {identification} (Dec: {int(identification, 16)})\n"
          f"  Flags and Offset: {flags_offset} (Dec: {int(flags_offset, 16)})\n"
          f"  TTL: {ttl} (Dec: {int(ttl, 16)})\n"
          f"  Protocol: {protocol} (Dec: {int(protocol, 16)})\n"
          f"  Header Checksum: {checksum} (Dec: {int(checksum, 16)})\n"
          f"  Source IP: {src_ip}\n"
          f"  Destination IP: {dst_ip}")


# Function to parse TCP packet
def parse_tcp_packet(hex_data):
    src_port = hex_data[68:72]
    dst_port = hex_data[72:76]
    seq_num = hex_data[76:84]
    ack_num = hex_data[84:92]
    data_offset = hex_data[92:93]
    flags = hex_data[94:96]
    window_size = hex_data[96:100]
    checksum = hex_data[100:104]
    urg_pointer = hex_data[104:108]

    print(f"TCP Packet:\n"
          f"  Source Port: {src_port} (Dec: {int(src_port, 16)})\n"
          f"  Destination Port: {dst_port} (Dec: {int(dst_port, 16)})\n"
          f"  Sequence Number: {seq_num} (Dec: {int(seq_num, 16)})\n"
          f"  Acknowledgment Number: {ack_num} (Dec: {int(ack_num, 16)})\n"
          f"  Data Offset: {data_offset} (Dec: {int(data_offset, 16)})\n"
          f"  Flags: {flags} (Bin: {bin(int(flags, 16))[2:].zfill(8)})\n"
          f"  Window Size: {window_size} (Dec: {int(window_size, 16)})\n"
          f"  Checksum: {checksum} (Dec: {int(checksum, 16)})\n"
          f"  Urgent Pointer: {urg_pointer} (Dec: {int(urg_pointer, 16)})")


# Function to parse UDP packet
def parse_udp_packet(hex_data):
    src_port = hex_data[68:72]
    dst_port = hex_data[72:76]
    length = hex_data[76:80]
    checksum = hex_data[80:84]

    print(f"UDP Packet:\n"
          f"  Source Port: {src_port} (Dec: {int(src_port, 16)})\n"
          f"  Destination Port: {dst_port} (Dec: {int(dst_port, 16)})\n"
          f"  Length: {length} (Dec: {int(length, 16)})\n"
          f"  Checksum: {checksum} (Dec: {int(checksum, 16)})")


# Function to handle each captured packet
def packet_callback(packet):
    # Convert the raw packet to hex format
    raw_data = bytes(packet)
    hex_data = raw_data.hex()

    # Process the Ethernet header
    print(f"\nCaptured Packet (Hex): {hex_data}")
    ether_type = parse_ethernet_header(hex_data)
    if ether_type == '0806':  # ARP
        parse_arp_packet(hex_data)
    elif ether_type == '0800':  # IPv4
        parse_ipv4_packet(hex_data)
        protocol = hex_data[46:48]
        if protocol == '06':  # TCP
            parse_tcp_packet(hex_data)
        elif protocol == '11':  # UDP
            parse_udp_packet(hex_data)


# Capture packets on a specified interface using a custom filter
def capture_packets(interface, capture_filter, packet_count, timeout):
    print(f"Packet capture on {interface} with filter: {capture_filter} ")
    sniff(iface=interface, filter=capture_filter, prn=packet_callback, count=packet_count, timeout=timeout)


def main():
    args = define_arguments()

    try:
        capture_packets(args.interface, args.filter, args.count, args.timeout)
    except Exception as e:
        print(f"Error: {e}")
        # capture_packets('et0', args.filter, args.count)


if __name__ == '__main__':
    main()


