from datetime import datetime, timezone
from features import PacketDirection, packet_flow_key

from features.flag_counts import FlagCount
from features.flow_bytes import FlowBytes
from features.packet_count import PacketCount
from features.packet_length import PacketLength
from features.packet_time import PacketTime
from utils.statistics import get_statistics

EXPIRED_UPDATE = 240
CLUMP_TIMEOUT = 1
ACTIVE_TIMEOUT = 0.005
BULK_BOUND = 4


class Flow:
    """
    Flow class for representing a flow in the network.
    """
    def __init__(self, packet, direction):
        self.protocol = None
        (
            self.src_ip,
            self.dst_ip,
            self.src_mac,
            self.dst_mac,
            self.src_port,
            self.dst_port
        ) = packet_flow_key.get_packet_flow_key(packet, direction)

        self.packets = []
        self.start_timestamp = 0
        self.latest_timestamp = 0
        self.flow_interarrival_time = []

        self.init_window_size = {
            PacketDirection.FORWARD: 0,
            PacketDirection.REVERSE: 0,
        }

        self.start_active = 0
        self.last_active = 0
        self.active = []
        self.idle = []

        self.forward_bulk_last_timestamp = 0
        self.forward_bulk_start_tmp = 0
        self.forward_bulk_count = 0
        self.forward_bulk_count_tmp = 0
        self.forward_bulk_duration = 0
        self.forward_bulk_packet_count = 0
        self.forward_bulk_size = 0
        self.forward_bulk_size_tmp = 0
        self.backward_bulk_last_timestamp = 0
        self.backward_bulk_start_tmp = 0
        self.backward_bulk_count = 0
        self.backward_bulk_count_tmp = 0
        self.backward_bulk_duration = 0
        self.backward_bulk_packet_count = 0
        self.backward_bulk_size = 0
        self.backward_bulk_size_tmp = 0

    def add_packet(self, packet, direction) -> None:
        """
        Add packet to the flow and update statistics
        :param direction:
        :param packet:
        :return:
        """
        # print("inside add packet")
        self.packets.append((packet, direction))
        # print("inside add packet 2")
        self._update_flow_bulk(packet, direction)
        # print("inside add packet 3")
        self._update_subflow(packet)

        if self.start_timestamp != 0:
            self.flow_interarrival_time.append(
                1e6 * (packet.timestamp - self.latest_timestamp)
            )
        self.latest_timestamp = max([packet.timestamp, self.latest_timestamp])

        if self.start_timestamp == 0:
            self.start_timestamp = packet.timestamp
            self.protocol = packet.trans_proto_number

    def _update_subflow(self, packet):
        last_timestamp = (
            self.latest_timestamp if self.latest_timestamp != 0 else packet.timestamp
        )
        if (packet.timestamp - last_timestamp) > CLUMP_TIMEOUT:
            self._update_active_idle(packet.timestamp - last_timestamp)

    def _update_active_idle(self, current_time):
        """Adds a packet to the current list of packets.

        """
        if (current_time - self.last_active) > ACTIVE_TIMEOUT:
            duration = abs(float(self.last_active - self.start_active))
            if duration > 0:
                self.active.append(1e6 * duration)
            self.idle.append(1e6 * (current_time - self.last_active))
            self.start_active = current_time
            self.last_active = current_time
        else:
            self.last_active = current_time

    def _update_flow_bulk(self, packet, direction):
        """
        Update flow bulk statistics
        :param packet:
        :param direction:
        :return:
        """
        payload_size = len(packet.payload) if packet.payload else 0
        # print(payload_size)
        if payload_size == 0:
            return

        if direction == PacketDirection.FORWARD:
            if self.backward_bulk_last_timestamp > self.forward_bulk_start_tmp:
                self.forward_bulk_start_tmp = 0
            if self.forward_bulk_start_tmp == 0:
                self.forward_bulk_start_tmp = packet.timestamp
                self.forward_bulk_last_timestamp = packet.timestamp
                self.forward_bulk_count_tmp = 1
                self.forward_bulk_size_tmp = payload_size
            else:
                if (
                        packet.timestamp - self.forward_bulk_last_timestamp
                ) > CLUMP_TIMEOUT:
                    self.forward_bulk_start_tmp = packet.timestamp
                    self.forward_bulk_last_timestamp = packet.timestamp
                    self.forward_bulk_count_tmp = 1
                    self.forward_bulk_size_tmp = payload_size
                else:  # Add to bulk
                    self.forward_bulk_count_tmp += 1
                    self.forward_bulk_size_tmp += payload_size
                    if self.forward_bulk_count_tmp == BULK_BOUND:
                        self.forward_bulk_count += 1
                        self.forward_bulk_packet_count += self.forward_bulk_count_tmp
                        self.forward_bulk_size += self.forward_bulk_size_tmp
                        self.forward_bulk_duration += (
                                packet.timestamp - self.forward_bulk_start_tmp
                        )
                    elif self.forward_bulk_count_tmp > BULK_BOUND:
                        self.forward_bulk_packet_count += 1
                        self.forward_bulk_size += payload_size
                        self.forward_bulk_duration += (
                                packet.timestamp - self.forward_bulk_last_timestamp
                        )
                    self.forward_bulk_last_timestamp = packet.timestamp
        else:
            if self.forward_bulk_last_timestamp > self.backward_bulk_start_tmp:
                self.backward_bulk_start_tmp = 0
            if self.backward_bulk_start_tmp == 0:
                self.backward_bulk_start_tmp = packet.timestamp
                self.backward_bulk_last_timestamp = packet.timestamp
                self.backward_bulk_count_tmp = 1
                self.backward_bulk_size_tmp = payload_size
            else:
                if (
                        packet.timestamp - self.backward_bulk_last_timestamp
                ) > CLUMP_TIMEOUT:
                    self.backward_bulk_start_tmp = packet.timestamp
                    self.backward_bulk_last_timestamp = packet.timestamp
                    self.backward_bulk_count_tmp = 1
                    self.backward_bulk_size_tmp = payload_size
                else:  # Add to bulk
                    self.backward_bulk_count_tmp += 1
                    self.backward_bulk_size_tmp += payload_size
                    if self.backward_bulk_count_tmp == BULK_BOUND:
                        self.backward_bulk_count += 1
                        self.backward_bulk_packet_count += self.backward_bulk_count_tmp
                        self.backward_bulk_size += self.backward_bulk_size_tmp
                        self.backward_bulk_duration += (
                                packet.timestamp - self.backward_bulk_start_tmp
                        )
                    elif self.backward_bulk_count_tmp > BULK_BOUND:
                        self.backward_bulk_packet_count += 1
                        self.backward_bulk_size += payload_size
                        self.backward_bulk_duration += (
                                packet.timestamp - self.backward_bulk_last_timestamp
                        )
                    self.backward_bulk_last_timestamp = packet.timestamp

    @property
    def duration(self):
        """
        Get the duration of the flow
        :return: Duration in seconds
        """
        return self.latest_timestamp - self.start_timestamp

    def get_features(self):
        """
        Calculate and return the statistical features of the flow
        :return: Dictionary
        """
        flow_bytes = FlowBytes(self)
        flag_count = FlagCount(self)
        packet_count = PacketCount(self)
        packet_length = PacketLength(self)
        packet_time = PacketTime(self)
        flow_iat = get_statistics(self.flow_interarrival_time)
        forward_iat = get_statistics(
            packet_time.get_packet_iat(PacketDirection.FORWARD)
        )
        backward_iat = get_statistics(
            packet_time.get_packet_iat(PacketDirection.REVERSE)
        )
        active_stat = get_statistics(self.active)
        idle_stat = get_statistics(self.idle)

        data = {
            # Basic IP information
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,  # 1
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "protocol": self.protocol,  # 2

            # Basic information from packet times
            "timestamp": packet_time.get_time_stamp(),  # 3
            "flow_duration": 1e6 * packet_time.get_duration(),  # 4
            "flow_bytes_s": flow_bytes.get_rate(),  # 17
            "flow_pkts_s": packet_count.get_rate(),  # 18
            "fwd_pkts_s": packet_count.get_rate(PacketDirection.FORWARD),   # 36
            "bwd_pkts_s": packet_count.get_rate(PacketDirection.REVERSE),   # 37

            # Count total packets by direction
            "total_fwd_pkts": packet_count.get_total(PacketDirection.FORWARD),   # 5
            "total_bwd_pkts": packet_count.get_total(PacketDirection.REVERSE),  # 6

            # Statistical info obtained from Packet lengths
            "tot_len_of_fwd_pkt": packet_length.get_total(PacketDirection.FORWARD),    # 7
            "tot_len_of_bwd_pkt": packet_length.get_total(PacketDirection.REVERSE),    # 8
            "fwd_pkt_len_max": float(packet_length.get_max(PacketDirection.FORWARD)),   # 9
            "fwd_pkt_len_min": float(packet_length.get_min(PacketDirection.FORWARD)),   # 10
            "fwd_pkt_len_mean": float(packet_length.get_mean(PacketDirection.FORWARD)),  # 11
            "fwd_pkt_len_std": float(packet_length.get_std(PacketDirection.FORWARD)),   # 12
            "bwd_pkt_len_max": float(packet_length.get_max(PacketDirection.REVERSE)),   # 13
            "bwd_pkt_len_min": float(packet_length.get_min(PacketDirection.REVERSE)),   # 14
            "bwd_pkt_len_mean": float(packet_length.get_mean(PacketDirection.REVERSE)),  # 15
            "bwd_pkt_len_std": float(packet_length.get_std(PacketDirection.REVERSE)),   # 16
            "pkt_len_max": packet_length.get_max(),     # 39
            "pkt_len_min": packet_length.get_min(),     # 38
            "pkt_len_mean": float(packet_length.get_mean()),    # 40
            "pkt_len_std": float(packet_length.get_std()),      # 41
            "pkt_len_var": float(packet_length.get_var()),      # 42
            "fwd_header_len": flow_bytes.get_forward_header_bytes(),    # 34
            "bwd_header_len": flow_bytes.get_reverse_header_bytes(),    # 35
            "fwd_seg_size_min": flow_bytes.get_min_forward_header_bytes(),  # 61
            "fwd_act_data_pkts": packet_count.has_payload(PacketDirection.FORWARD),     # 60

            # Flows Inter arrival Time
            "flow_iat_mean": float(flow_iat["mean"]),   # 19
            "flow_iat_max": float(flow_iat["max"]),     # 21
            "flow_iat_min": float(flow_iat["min"]),     # 22
            "flow_iat_std": float(flow_iat["std"]),     # 20
            "fwd_iat_tot": forward_iat["total"],        # 23
            "fwd_iat_max": float(forward_iat["max"]),   # 26
            "fwd_iat_min": float(forward_iat["min"]),   # 27
            "fwd_iat_mean": float(forward_iat["mean"]),     # 24
            "fwd_iat_std": float(forward_iat["std"]),       # 25
            "bwd_iat_tot": float(backward_iat["total"]),    # 28
            "bwd_iat_max": float(backward_iat["max"]),      # 31
            "bwd_iat_min": float(backward_iat["min"]),      # 32
            "bwd_iat_mean": float(backward_iat["mean"]),    # 29
            "bwd_iat_std": float(backward_iat["std"]),      # 30

            # Flags statistics
            "fwd_psh_flags": flag_count.has_flag("PSH", PacketDirection.FORWARD),   # 33
            "bwd_psh_flags": flag_count.has_flag("PSH", PacketDirection.REVERSE),
            "fwd_urg_flags": flag_count.has_flag("URG", PacketDirection.FORWARD),
            "bwd_urg_flags": flag_count.has_flag("URG", PacketDirection.REVERSE),
            "fin_flag_cnt": flag_count.has_flag("FIN"),     # 43
            "syn_flag_cnt": flag_count.has_flag("SYN"),     # 44
            "rst_flag_cnt": flag_count.has_flag("RST"),     # 45
            "psh_flag_cnt": flag_count.has_flag("PSH"),     # 46
            "ack_flag_cnt": flag_count.has_flag("ACK"),     # 47
            "urg_flag_cnt": flag_count.has_flag("URG"),     # 48
            "ece_flag_cnt": flag_count.has_flag("ECE"),     # 49

            # Response Time
            "down_up_ratio": packet_count.get_down_up_ratio(),  # 50
            "pkt_size_avg": packet_length.get_avg(),    # 51
            "init_fwd_win_byts": self.init_window_size[PacketDirection.FORWARD],    # 58
            "init_bwd_win_byts": self.init_window_size[PacketDirection.REVERSE],    # 59
            "active_max": float(active_stat["max"]),    # 64
            "active_min": float(active_stat["min"]),    # 65
            "active_mean": float(active_stat["mean"]),  # 62
            "active_std": float(active_stat["std"]),    # 63
            "idle_max": float(idle_stat["max"]),        # 68
            "idle_min": float(idle_stat["min"]),        # 69
            "idle_mean": float(idle_stat["mean"]),     # 66
            "idle_std": float(idle_stat["std"]),       # 67
            "fwd_byts_b_avg": float(
                flow_bytes.get_bytes_per_bulk(PacketDirection.FORWARD)
            ),
            "fwd_pkts_b_avg": float(
                flow_bytes.get_packets_per_bulk(PacketDirection.FORWARD)
            ),
            "bwd_byts_b_avg": float(
                flow_bytes.get_bytes_per_bulk(PacketDirection.REVERSE)
            ),
            "bwd_pkts_b_avg": float(
                flow_bytes.get_packets_per_bulk(PacketDirection.REVERSE)
            ),
            "fwd_blk_rate_avg": float(
                flow_bytes.get_bulk_rate(PacketDirection.FORWARD)
            ),
            "bwd_blk_rate_avg": float(
                flow_bytes.get_bulk_rate(PacketDirection.REVERSE)
            ),
        }

        # Duplicated features
        data["fwd_seg_size_avg"] = data["fwd_pkt_len_mean"]     # 52
        data["bwd_seg_size_avg"] = data["bwd_pkt_len_mean"]     # 53
        data["cwe_flag_count"] = data["fwd_urg_flags"]
        data["subflow_fwd_pkts"] = data["total_fwd_pkts"]     # 54
        data["subflow_bwd_pkts"] = data["total_bwd_pkts"]     # 56
        data["subflow_fwd_byts"] = data["tot_len_of_fwd_pkt"]  # 55
        data["subflow_bwd_byts"] = data["tot_len_of_bwd_pkt"]  # 57

        return data

    def __str__(self):
        return str(f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}")
