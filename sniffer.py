import socket
import struct
import textwrap

def main():
    # Create a raw socket to capture all network packets (Linux/Unix standard)
    # Note: Requires root/sudo privileges to execute
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except PermissionError:
        print("[CRITICAL] Administrative privileges required. Run with sudo.")
        return

    print("[START] Raw Network Sniffer Active. Listening for packets...\n")

    try:
        while True:
            raw_data, addr = conn.recvfrom(65535)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            
            # Protocol 8 means IPv4
            if eth_proto == 8:
                (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
                print(f"--- [IPv4 Packet Captured] ---")
                print(f"Source IP: {src} -> Destination IP: {target}")
                print(f"Protocol: {proto} | TTL: {ttl}")

                # TCP Protocol Analysis
                if proto == 6:
                    src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin = tcp_segment(data)
                    print(f"|-- Protocol: TCP")
                    print(f"|   Source Port: {src_port} -> Destination Port: {dest_port}")
                    print(f"|   Flags - SYN: {flag_syn}, ACK: {flag_ack}, FIN: {flag_fin}, RST: {flag_rst}")
                    
                    # Basic AppSec Rule: Alert if someone scans via SYN flags without ACK
                    if flag_syn == 1 and flag_ack == 0:
                        print("|   [ALERT] Potential Stealth SYN Port Scan Signature Detected!")

                # UDP Protocol Analysis
                elif proto == 17:
                    src_port, dest_port, length, data = udp_segment(data)
                    print(f"|-- Protocol: UDP")
                    print(f"|   Source Port: {src_port} -> Destination Port: {dest_port}")
                
                print("\n")

    except KeyboardInterrupt:
        print("\n[STOP] Sniffer execution halted by operator.")

# Unpack Ethernet Frame Headers
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Format MAC Address string cleanly (AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

# Unpack IPv4 Packet Headers
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4_format(src), ipv4_format(target), data[header_length:]

# Format raw bytes to human-readable IP string (e.g., 192.168.1.1)
def ipv4_format(addr):
    return '.'.join(map(str, addr))

# Unpack TCP Segment Headers
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin

# Unpack UDP Segment Headers
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H H', data[:6])
    return src_port, dest_port, size, data[6:]

if __name__ == '__main__':
    main()
