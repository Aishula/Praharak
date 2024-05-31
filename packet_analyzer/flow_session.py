from features import packet_flow_key
from flow import Flow
from features.network_information import Packet
from features import PacketDirection


class FlowSession:
    """
    Manages network flow sessions.
    """

    def __init__(self):
        self.flows = {}
        self.expiration_threshold = 40
        self.expiry_duration = 60
        self.garbage_collection_threshold = 50  # After 100 packet processed
        self.packet_count = 0

    def process_packet(self, raw_data, timestamp):
        """
        Process a packet and add to the appropriate flow.
        """
        packet = Packet(raw_data, timestamp)
        count = 0
        # Check if the packet contains non field or not
        # if not, then process the packet otherwise ignore the packet
        if (packet.src_ip is None or packet.dst_ip is None or
                packet.src_mac is None or packet.dst_mac is None or
                packet.src_port is None or packet.dst_port is None):
            return

        direction = self._get_packet_direction(packet)
        flow_key = packet_flow_key.get_packet_flow_key(packet, direction)
        print("FLOW ID: ", flow_key)
        # print(self.flows.values())
        # print(direction)
        flow = self.flows.get((flow_key, count))

        self.packet_count += 1

        # if flow id is not in flows, add it
        # Otherwise add packet to the existing flow
        if flow is None:
            flow = Flow(packet, direction)
            self.flows[(flow_key, count)] = flow

        elif packet.timestamp - flow.latest_timestamp > self.expiration_threshold:
            expired = self.expiration_threshold
            while packet.timestamp - flow.latest_timestamp > expired:
                count += 1
                expired += self.expiration_threshold
                flow = self.flows.get((flow_key, count))

                if flow is None:
                    flow = Flow(packet, direction)
                    self.flows[(flow_key, count)] = flow
                    break

        elif "F" in str(packet.flags):
            flow.add_packet(packet, direction)
            self._perform_garbage_collection(packet.timestamp)
            return

        flow.add_packet(packet, direction)

        if self.packet_count % self.garbage_collection_threshold == 0 or (
                flow.duration > self.expiry_duration):
            self._perform_garbage_collection(packet.timestamp)

    def _get_flows(self):
        return self.flows.values()

    def _perform_garbage_collection(self, latest_timestamp) -> None:
        """
        Remove flows that are either expired or reached the garbage collection threshold
        """
        print("Performing garbage collection check...")  # Debugging line
        print(
            f"Current number of flows: {len(self.flows)}")  # Debugging line

        keys = list(self.flows.keys())
        for k in keys:
            flow = self.flows.get(k)
            if (latest_timestamp is None or
                    latest_timestamp - flow.latest_timestamp > self.expiration_threshold or
                    flow.duration > self.expiry_duration):
                data = flow.get_features()
                print(data)
                print(len(data))
                del self.flows[k]

    def _get_packet_direction(self, packet):
        """
        Determine the direction of a packet, either forward or backward
        :param packet:
        :return: PacketDirection
        """
        flow_key_forward = packet_flow_key.get_packet_flow_key(packet, PacketDirection.FORWARD)
        flow_key_backward = packet_flow_key.get_packet_flow_key(packet, PacketDirection.REVERSE)
        if flow_key_forward in self.flows:
            return PacketDirection.FORWARD

        elif flow_key_backward in self.flows:
            return PacketDirection.REVERSE
        else:
            return PacketDirection.FORWARD  # First packet in a new flow
