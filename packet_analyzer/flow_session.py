from flow import Flow
from features.network_information import Packet
from features import PacketDirection


class FlowSession:
    """
    Manages network flow sessions.
    """
    def __init__(self):
        self.flows = {}
        self.expiration_threshold = 120  # 2 minutes
        self.garbage_collection_threshold = 100  # After 100 packet processed
        self.packet_count = 0

    def process_packet(self, raw_data):
        """
        Process a packet and add to the appropriate flow.
        """
        packet = Packet(raw_data).get_packet_details()
        direction = self._get_packet_direction(packet)
        flow_key = self._get_packet_flow_key(packet, direction)
        # print("FLOW ID: ", flow_key)

        # if flow id is not in flows, add it
        # Otherwise add packet to the existing flow
        if flow_key not in self.flows:
            self.flows[flow_key] = Flow(flow_key)
        self.flows[flow_key].add_packet(packet, direction)
        self.packet_count += 1

        # finally call to garbage collection
        self._perform_garbage_collection()

    def _perform_garbage_collection(self):
        """
        Remove flows that are either expired or reached the garbage collection threshold
        """
        if len(self.flows) % self.garbage_collection_threshold == 0:
            keys_to_delete = []
            for flow_id, flow in self.flows.items():
                if flow.is_expired(self.expiration_threshold):
                    # If flow is expired, get all the features and remove it
                    features = flow.get_features()
                    print(features)
                    keys_to_delete.append(flow_id)
            for flow_id in keys_to_delete:
                del self.flows[flow_id]

    @staticmethod
    def _get_packet_flow_key(packet, direction) -> tuple:
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

    def _get_packet_direction(self, packet):
        """
        Determine the direction of a packet, either forward or backward
        :param packet:
        :return: PacketDirection
        """
        flow_key_forward = self._get_packet_flow_key(packet, PacketDirection.FORWARD)
        flow_key_backward = self._get_packet_flow_key(packet, PacketDirection.BACKWARD)
        if flow_key_forward in self.flows:
            return PacketDirection.FORWARD

        elif flow_key_backward in self.flows:
            return PacketDirection.BACKWARD
        else:
            return PacketDirection.FORWARD  # First packet in a new flow
