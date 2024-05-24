import struct
import socket
from statistics import mean, stdev
from datetime import datetime, timezone

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
    dest_mac, src_mac, proto_num = struct.unpack('!6s6sH', raw_data[:14])
    dest_mac_str = mac_address_to_str(dest_mac)
    src_mac_str = mac_address_to_str(src_mac)
    proto_name = get_protocol_name(proto_num)
    data = raw_data[14:]
    return dest_mac_str, src_mac_str, proto_num, proto_name, data


def parse_ipv4_header(data):
    # Extract version and header length directly
    version_header_length = data[0]
    header_length = (version_header_length & 0x0F) * 4

    # Unpack required fields from the IPv4 header
    ttl, next_header, src, dest = struct.unpack('!8xBB2x4s4s', data[:20])

    # Convert binary IP addresses to readable format
    src_ip = '.'.join(map(str, src))
    dest_ip = '.'.join(map(str, dest))

    # Return parsed fields and the payload
    return src_ip, dest_ip, next_header, ttl, data[header_length:]


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


class PacketAnalyzer:
    def __init__(self, packet_handler):
        self.packet_handler = packet_handler
        self.src_mac = None
        self.dest_mac = None
        self.src_ip = None
        self.dest_ip = None
        self.net_proto_number = None
        self.net_proto_name = None
        self.trans_proto_number = None
        self.trans_proto_name = None
        self.ttl = None
        self.flow_start_time = None
        self.flow_duration = 0
        self.total_fwd_packets = 0
        self.total_bwd_packets = 0
        self.fwd_packet_lengths = []
        self.bwd_packet_lengths = []
        self.fwd_iat = []
        self.bwd_iat = []
        self.flow_bytes_per_second = 0
        self.flow_packets_per_second = 0
        self.fwd_psh_flags = 0
        self.bwd_psh_flags = 0
        self.fwd_header_length = 0
        self.bwd_header_length = 0
        self.syn_flag_count = 0
        self.rst_flag_count = 0
        self.cwe_flag_count = 0
        self.down_up_ratio = 0
        self.idle_times = []
        self.prev_fwd_packet_time = None
        self.prev_bwd_packet_time = None

    def analyze(self, raw_data, timestamp):
        try:
            self.dest_mac, self.src_mac, self.net_proto_number, self.net_proto_name, data = (
                parse_ethernet_header(raw_data))

            if self.net_proto_number == 0x0800:  # IPv4
                self.src_ip, self.dest_ip, self.trans_proto_number, self.ttl, payload = (
                    parse_ipv4_header(data))

            elif self.net_proto_name == 0x86DD:  # IPv6
                self.src_ip, self.dest_ip, self.trans_proto_number, self.ttl, payload = (
                    parse_ipv6_header(data))
            else:
                return

            self.trans_proto_name = get_transport_protocol_name(self.net_proto_number, self.trans_proto_number)

            if self.trans_proto_number == 6:  # TCP
                src_port, dst_port, seq, ack, header_length, flags, window, checksum, urg_ptr, payload = (
                    parse_tcp_header(payload))
                self.update_statistics('TCP', self.src_ip, self.dest_ip, src_port, dst_port, len(payload),
                                       timestamp, flags, header_length)

            elif self.trans_proto_number == 17:  # UDP
                src_port, dst_port, length, checksum, payload = parse_udp_header(payload)
                self.update_statistics('UDP', self.src_ip, self.dest_ip, src_port, dst_port,
                                       len(payload), timestamp, 0, 8)
                self.calculate_final_statistics()

        except Exception as e:
            print(f"Error processing packet: {e}")

    def update_statistics(self, protocol, src_ip, dst_ip, src_port, dst_port, payload_length, timestamp, flags,
                          header_length):
        if self.flow_start_time is None:
            self.flow_start_time = timestamp

        current_timestamp = datetime.now(timezone.utc)

        self.flow_duration = (current_timestamp - self.flow_start_time).total_seconds()
        self.flow_bytes_per_second = (sum(self.fwd_packet_lengths) + sum(self.bwd_packet_lengths)) / self.flow_duration
        self.flow_packets_per_second = (self.total_fwd_packets + self.total_bwd_packets) / self.flow_duration

        if src_ip == self.src_ip:
            self.total_fwd_packets += 1
            self.fwd_packet_lengths.append(payload_length)
            if self.prev_fwd_packet_time is not None:
                self.fwd_iat.append((current_timestamp - self.prev_fwd_packet_time).total_seconds())
            self.prev_fwd_packet_time = current_timestamp
            self.fwd_header_length += header_length
            if flags & 0x08:  # PSH flag
                self.fwd_psh_flags += 1
        else:
            self.total_bwd_packets += 1
            self.bwd_packet_lengths.append(payload_length)
            if self.prev_bwd_packet_time is not None:
                self.bwd_iat.append((current_timestamp - self.prev_bwd_packet_time).total_seconds())
            self.prev_bwd_packet_time = current_timestamp
            self.bwd_header_length += header_length
            if flags & 0x08:  # PSH flag
                self.bwd_psh_flags += 1

        self.syn_flag_count += flags & 0x02
        self.rst_flag_count += flags & 0x04
        self.cwe_flag_count += flags & 0x80
        self.down_up_ratio = (self.total_fwd_packets / self.total_bwd_packets) if self.total_bwd_packets > 0 else 0

        self.idle_times.append((timestamp - self.flow_start_time).total_seconds())

    def calculate_final_statistics(self):
        fwd_packet_length_mean = mean(self.fwd_packet_lengths) if self.fwd_packet_lengths else 0
        fwd_packet_length_std = stdev(self.fwd_packet_lengths) if len(self.fwd_packet_lengths) > 1 else 0
        bwd_packet_length_mean = mean(self.bwd_packet_lengths) if self.bwd_packet_lengths else 0
        bwd_packet_length_std = stdev(self.bwd_packet_lengths) if len(self.bwd_packet_lengths) > 1 else 0
        fwd_iat_mean = mean(self.fwd_iat) if self.fwd_iat else 0
        fwd_iat_std = stdev(self.fwd_iat) if len(self.fwd_iat) > 1 else 0
        bwd_iat_mean = mean(self.bwd_iat) if self.bwd_iat else 0
        bwd_iat_std = stdev(self.bwd_iat) if len(self.bwd_iat) > 1 else 0
        idle_mean = mean(self.idle_times) if self.idle_times else 0
        idle_std = stdev(self.idle_times) if len(self.idle_times) > 1 else 0

        features = {
            'Protocol': self.trans_proto_number,
            'Flow Duration': self.flow_duration,
            'Total Fwd Packets': self.total_fwd_packets,
            'Total Backward Packets': self.total_bwd_packets,
            'Fwd Packets Length Total': sum(self.fwd_packet_lengths),
            'Bwd Packets Length Total': sum(self.bwd_packet_lengths),
            'Fwd Packet Length Max': max(self.fwd_packet_lengths, default=0),
            'Fwd Packet Length Min': min(self.fwd_packet_lengths, default=0),
            'Fwd Packet Length Mean': fwd_packet_length_mean,
            'Fwd Packet Length Std': fwd_packet_length_std,
            'Bwd Packet Length Max': max(self.bwd_packet_lengths, default=0),
            'Bwd Packet Length Min': min(self.bwd_packet_lengths, default=0),
            'Bwd Packet Length Mean': bwd_packet_length_mean,
            'Flow Bytes/s': self.flow_bytes_per_second,
            'Flow Packets/s': self.flow_packets_per_second,
            'Flow IAT Mean': fwd_iat_mean + bwd_iat_mean,
            'Flow IAT Std': fwd_iat_std + bwd_iat_std,
            'Flow IAT Max': max(self.fwd_iat + self.bwd_iat, default=0),
            'Flow IAT Min': min(self.fwd_iat + self.bwd_iat, default=0),
            'Fwd IAT Min': min(self.fwd_iat, default=0),
            'Bwd IAT Total': sum(self.bwd_iat),
            'Bwd IAT Mean': bwd_iat_mean,
            'Bwd IAT Std': bwd_iat_std,
            'Idle Mean': idle_mean,
            'Idle Std': idle_std,
            'Fwd Header Length': self.fwd_header_length,
            'Bwd Header Length': self.bwd_header_length,
            'Fwd PSH Flags': self.fwd_psh_flags,
            'Bwd PSH Flags': self.bwd_psh_flags,
            'SYN Flag Count': self.syn_flag_count,
            'RST Flag Count': self.rst_flag_count,
            'CWE Flag Count': self.cwe_flag_count,
            'Down/Up Ratio': self.down_up_ratio
        }
        self.packet_handler.handle_packet(features)
