from flow import Flow
from features.network_information import Packet


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
        flow_id, direction = self._get_flow_id(packet)
        print("FLOW ID: ", flow_id)

        # if flow id is not in flows, add it
        # Otherwise add packet to the existing flow
        if flow_id not in self.flows:
            self.flows[flow_id] = Flow(flow_id)
        self.flows[flow_id].add_packet(packet)

        # finally call to garbage collection
        self._perform_garbage_collection()

    def _get_flow_id(self, packet):
        """
        Generate the unique flow id for the packet and determine packet direction
        """
        return hash((packet["src_ip"], packet["dst_ip"], packet["src_port"], packet["dst_port"]))

    def _perform_garbage_collection(self):
        """
        Remove flows that are either expired or reached the garbage collection threshold
        """
        if len(self.flows) % self.garbage_collection_threshold == 0:
            keys_to_delete = []
            for flow_id, flow in self.flows.items():
                if flow.is_expired(self.expiration_threshold):
                    keys_to_delete.append(flow_id)
            for flow_id in keys_to_delete:
                del self.flows[flow_id]
