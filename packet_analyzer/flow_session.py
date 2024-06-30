from features import packet_flow_key
from flow import Flow
from features.network_information import Packet
from features import PacketDirection
from communication import Communication
import asyncio
from ai_model import ai_model


class FlowSession:
    """
    Manages network flow sessions.
    """

    def __init__(self):
        self.flows = {}
        self.expiration_threshold = 40
        self.expiry_duration = 60
        self.garbage_collection_threshold = 100  # After 100 packet processed
        self.packet_count = 0
        self.communication = Communication()

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

        # print("Dir from fun call", self._get_packet_direction(packet, count))

        # Consider the direction is forward
        # direction = PacketDirection.FORWARD
        # # check if the flow exists
        # flow_key = packet_flow_key.get_packet_flow_key(packet, direction)
        # flow = self.flows.get((flow_key, count))
        # print("fwd (first test)", flow)

        # self.packet_count += 1
        #
        # # If there is no existing forward flow, then there might be reverse with count 0
        # if flow is None:
        #     direction = PacketDirection.REVERSE
        #     flow_key = packet_flow_key.get_packet_flow_key(packet, direction)
        #     flow = self.flows.get((flow_key, count))
        #     # print("bwd (first test)", flow)

        # If no flow exists in above case, create new fwd
        # if flow is None:
        #     direction = PacketDirection.FORWARD
        #     flow = Flow(packet, direction)
        #     flow_key = packet_flow_key.get_packet_flow_key(packet, direction)
        #     self.flows[(flow_key, count)] = flow
        #     # print("fwd (new obj)", flow)

        direction = self._get_packet_direction(packet, count)
        flow_key = packet_flow_key.get_packet_flow_key(packet, direction)
        # print("FLOW ID: ", flow_key)
        # print(self.flows.values())
        # print(direction)
        flow = self.flows.get((flow_key, count))

        self.packet_count += 1

        # if flow id is not in flows, add it
        # Otherwise add packet to the existing flow
        if flow is None:
            flow = Flow(packet, direction)
            self.flows[(flow_key, count)] = flow

        # Flow for a packet is found but time is expired
        elif packet.timestamp - flow.latest_timestamp > self.expiration_threshold:
            expired = self.expiration_threshold
            while packet.timestamp - flow.latest_timestamp > expired:
                count += 1
                expired += self.expiration_threshold
                flow = self.flows.get((flow_key, count))

                if flow is None:
                    direction = PacketDirection.FORWARD
                    flow = Flow(packet, direction)
                    self.flows[(flow_key, count)] = flow
                    # print("fwd (time expired)", flow)
                    break

        elif "F" in str(packet.flags):
            flow.add_packet(packet, direction)
            self._perform_garbage_collection(packet.timestamp)
            return

        # print("Dir from Calc", direction)
        # print("---------------------")
        # Finally add packet to the flow
        flow.add_packet(packet, direction)

        # Pass the flow to garbage collection
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
                features = [
                    data["dst_port"],  # 1
                    data["protocol"],  # 2
                    data["timestamp"],  # 3
                    data["flow_duration"],  # 4
                    data["total_fwd_pkts"],  # 5
                    data["total_bwd_pkts"],  # 6
                    data["tot_len_of_fwd_pkt"],  # 7
                    data["tot_len_of_bwd_pkt"],  # 8
                    data["fwd_pkt_len_max"],  # 9
                    data["fwd_pkt_len_min"],  # 10
                    data["fwd_pkt_len_mean"],  # 11
                    data["fwd_pkt_len_std"],  # 12
                    data["bwd_pkt_len_max"],  # 13
                    data["bwd_pkt_len_min"],  # 14
                    data["bwd_pkt_len_mean"],  # 15
                    data["bwd_pkt_len_std"],  # 16
                    data["flow_bytes_s"],  # 17
                    data["flow_pkts_s"],  # 18
                    data["flow_iat_mean"],  # 19
                    data["flow_iat_std"],  # 20
                    data["flow_iat_max"],  # 21
                    data["flow_iat_min"],  # 22
                    data["fwd_iat_tot"],  # 23
                    data["fwd_iat_mean"],  # 24
                    data["fwd_iat_std"],  # 25
                    data["fwd_iat_max"],  # 26
                    data["fwd_iat_min"],  # 27
                    data["bwd_iat_tot"],  # 28
                    data["bwd_iat_mean"],  # 29
                    data["bwd_iat_std"],  # 30
                    data["bwd_iat_max"],  # 31
                    data["bwd_iat_min"],  # 32
                    data["fwd_psh_flags"],  # 33
                    data["fwd_header_len"],  # 34
                    data["bwd_header_len"],  # 35
                    data["fwd_pkts_s"],  # 36
                    data["bwd_pkts_s"],  # 37
                    data["pkt_len_min"],  # 38
                    data["pkt_len_max"],  # 39
                    data["pkt_len_mean"],  # 40
                    data["pkt_len_std"],  # 41
                    data["pkt_len_var"],  # 42
                    data["fin_flag_cnt"],  # 43
                    data["syn_flag_cnt"],  # 44
                    data["rst_flag_cnt"],  # 45
                    data["psh_flag_cnt"],  # 46
                    data["ack_flag_cnt"],  # 47
                    data["urg_flag_cnt"],  # 48
                    data["ece_flag_cnt"],  # 49
                    data["down_up_ratio"],  # 50
                    data["pkt_size_avg"],  # 51
                    data["fwd_seg_size_avg"],  # 52
                    data["bwd_seg_size_avg"],  # 53
                    data["subflow_fwd_pkts"],  # 54
                    data["subflow_fwd_byts"],  # 55
                    data["subflow_bwd_pkts"],  # 56
                    data["subflow_bwd_byts"],  # 57
                    data["init_fwd_win_byts"],  # 58
                    data["init_bwd_win_byts"],  # 59
                    data["fwd_act_data_pkts"],  # 60
                    data["fwd_seg_size_min"],  # 61
                    data["active_mean"],  # 62
                    data["active_std"],  # 63
                    data["active_max"],  # 64
                    data["active_min"],  # 65
                    data["idle_mean"],  # 66
                    data["idle_std"],  # 67
                    data["idle_max"],  # 68
                    data["idle_min"],  # 69
                ]
                result = ai_model.predict(features)
                print(data, result)
                # asyncio.run(self.communication.communicate(data))
                del self.flows[k]

    def _get_packet_direction(self, packet, count):
        """
        Determine the direction of a packet, either forward or backward
        :param packet:
        :return: PacketDirection
        """
        flow_key_forward = packet_flow_key.get_packet_flow_key(packet, PacketDirection.FORWARD)
        flow_key_backward = packet_flow_key.get_packet_flow_key(packet, PacketDirection.REVERSE)
        if (flow_key_forward, count) in self.flows:
            return PacketDirection.FORWARD

        elif (flow_key_backward, count) in self.flows:
            return PacketDirection.REVERSE
        else:
            return PacketDirection.FORWARD  # First packet in a new flow
