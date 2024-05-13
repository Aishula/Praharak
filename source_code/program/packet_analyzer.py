import struct


class PacketAnalyzer:
    def __init__(self, packet_handler):
        self.packet_handler = packet_handler

    def analyze(self, raw_data):
        dest, src, proto , data = self.mac_header(raw_data)
        print(f"Destination: {dest}, Source: {src}, Protocol: {proto}")
        # features = self.extract_features(data)
        # self.packet_handler.handle_packet(features)

    def mac_address_to_str(self, mac_address):
        # Convert MAC address from hexadecimal to colon-separated format
        return ':'.join('{:02x}'.format(byte) for byte in mac_address)

    def mac_header(self, raw_data):
        dest_mac = self.mac_address_to_str(raw_data[:6])
        src_mac = self.mac_address_to_str(raw_data[6:12])
        proto_num = int.from_bytes(raw_data[12:14], byteorder='big')
        # proto_name = self.PROTOCOL_MAP.get(proto_num, "Unknown")
        data = raw_data[14:]
        return dest_mac, src_mac, proto_num, data

    def extract_features(self, packet_data):
        pass
