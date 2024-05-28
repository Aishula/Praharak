import struct
import socket

PROTOCOL_MAP = {
    0x0800: 'IPv4',
    0x86DD: 'IPv6',
    0x0806: 'ARP',
}

TRANSPORT_PROTOCOLS = {
    6: 'TCP',
    17: 'UDP',
    58: 'ICMPv6',
    1: 'ICMP'
}


def get_protocol_name(proto_num):
    return PROTOCOL_MAP.get(proto_num, 'Unknown')


def mac_address_to_str(mac_address):
    return ':'.join('{:02x}'.format(byte) for byte in mac_address)


def parse_ethernet_header(raw_data):
    dst_mac, src_mac, proto_num = struct.unpack('!6s6sH', raw_data[:14])
    dst_mac_str = mac_address_to_str(dst_mac)
    src_mac_str = mac_address_to_str(src_mac)
    proto_name = get_protocol_name(proto_num)
    data = raw_data[14:]
    return dst_mac_str, src_mac_str, proto_num, proto_name, data


def parse_ipv4_header(data):
    # Extract version and header length directly
    version_header_length = data[0]
    header_length = (version_header_length & 0x0F) * 4

    # Unpack required fields from the IPv4 header
    ttl, next_header, src, dest = struct.unpack('!8xBB2x4s4s', data[:20])

    # Convert binary IP addresses to readable format
    src_ip = '.'.join(map(str, src))
    dst_ip = '.'.join(map(str, dest))

    # Return parsed fields and the payload
    return src_ip, dst_ip, next_header, ttl, data[header_length:]


def parse_ipv6_header(data):
    # Unpack the IPv6 header fields using struct
    version_traffic_flow, payload_length, next_header, hop_limit, src_ip, dst_ip = (
        struct.unpack('!I H B B 16s 16s', data[:40]))
    # Convert binary IPv6 addresses to human-readable strings
    src_ip = socket.inet_ntop(socket.AF_INET6, src_ip)
    dst_ip = socket.inet_ntop(socket.AF_INET6, dst_ip)

    # Extract the payload data
    payload = data[40:]

    # Rename hop_limit to ttl for consistency
    ttl = hop_limit

    return src_ip, dst_ip, next_header, ttl, payload


def get_transport_protocol_name(ip_version, next_header):
    return TRANSPORT_PROTOCOLS.get(next_header, 'Unknown')


def parse_tcp_header(data):
    src_port, dst_port, seq, ack, offset_reserved, flags, window, checksum, urg_ptr = (
        struct.unpack('!HHIIBBHHH', data[:20]))
    header_length = (offset_reserved >> 12) * 4
    flags = offset_reserved & 0x3F
    payload = data[header_length:]
    return src_port, dst_port, seq, ack, header_length, flags, window, checksum, urg_ptr, payload


def parse_udp_header(data):
    src_port, dst_port, length, checksum = struct.unpack('!HHHH', data[:8])
    payload = data[8:]
    return src_port, dst_port, length, checksum, payload


class Packet:
    """
    Represents a packet
    """
    def __init__(self, raw_data):
        self.raw_data = raw_data
        self.src_mac = None
        self.dst_mac = None
        self.src_ip = None
        self.dst_ip = None
        self.net_proto_number = None
        self.net_proto_name = None
        self.trans_proto_number = None
        self.trans_proto_name = None
        self.ttl = None
        self.src_port = None
        self.dst_port = None
        self._analyze()

    def _analyze(self):
        """Parse raw packet data and extract relevant information."""
        try:
            self.dst_mac, self.src_mac, self.net_proto_number, self.net_proto_name, data = (
                parse_ethernet_header(self.raw_data))

            if self.net_proto_number == 0x0800:  # IPv4
                self.src_ip, self.dst_ip, self.trans_proto_number, self.ttl, payload = (
                    parse_ipv4_header(data))

            elif self.net_proto_name == 0x86DD:  # IPv6
                self.src_ip, self.dst_ip, self.trans_proto_number, self.ttl, payload = (
                    parse_ipv6_header(data))
            else:
                return

            self.trans_proto_name = get_transport_protocol_name(self.net_proto_number, self.trans_proto_number)

            if self.trans_proto_number == 6:  # TCP
                self.src_port, self.dst_port, seq, ack, header_length, flags, window, checksum, urg_ptr, payload = (
                    parse_tcp_header(payload))

            elif self.trans_proto_number == 17:  # UDP
                self.src_port, self.dst_port, length, checksum, payload = parse_udp_header(payload)

            else:
                return

        except Exception as e:
            print(f"Error processing packet: {e}")

    def get_packet_details(self):
        return {
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "raw_data": self.raw_data
        }
