from .packet_direction import PacketDirection


def get_packet_flow_key(packet, direction) -> tuple:
    """
    Generate the unique flow id for the packet and determine packet direction
    :param packet: Packet object from features.network_information
    :param direction: PacketDirection
    :return: String
    """
    if direction == PacketDirection.FORWARD:
        src_ip = packet['src_ip']
        dst_ip = packet['dst_ip']
        src_mac = packet['src_mac']
        dst_mac = packet['dst_mac']
        src_port = packet['src_port']
        dst_port = packet['dst_port']
    else:
        src_ip = packet['dst_ip']
        dst_ip = packet['src_ip']
        src_mac = packet['dst_mac']
        dst_mac = packet['src_mac']
        src_port = packet['dst_port']
        dst_port = packet['src_port']

    return src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port
