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
        self.packets.append((packet, direction))
        self._update_flow_bulk(packet, direction)
        self._update_subflow(packet)

        if self.start_timestamp != 0:
            self.flow_interarrival_time.append(
                1e6 * (packet.timestamp - self.latest_timestamp)
            )
        self.latest_timestamp = max([packet.timestamp, self.latest_timestamp])

        if self.start_timestamp == 0:
            self.start_timestamp = packet.timestamp
            self.protocol = packet.proto

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
        payload_size = len(PacketCount.get_payload(packet))
        if payload_size == 0:
            return

        if direction == PacketDirection.FORWARD:
            if self.backward_bulk_last_timestamp > self.forward_bulk_start_tmp:
                self.forward_bulk_start_tmp = 0
            if self.forward_bulk_start_tmp == 0:
                self.forward_bulk_start_tmp = packet.time
                self.forward_bulk_last_timestamp = packet.time
                self.forward_bulk_count_tmp = 1
                self.forward_bulk_size_tmp = payload_size
            else:
                if (
                        packet.time - self.forward_bulk_last_timestamp
                ) > CLUMP_TIMEOUT:
                    self.forward_bulk_start_tmp = packet.time
                    self.forward_bulk_last_timestamp = packet.time
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
                                packet.time - self.forward_bulk_start_tmp
                        )
                    elif self.forward_bulk_count_tmp > BULK_BOUND:
                        self.forward_bulk_packet_count += 1
                        self.forward_bulk_size += payload_size
                        self.forward_bulk_duration += (
                                packet.time - self.forward_bulk_last_timestamp
                        )
                    self.forward_bulk_last_timestamp = packet.time
        else:
            if self.forward_bulk_last_timestamp > self.backward_bulk_start_tmp:
                self.backward_bulk_start_tmp = 0
            if self.backward_bulk_start_tmp == 0:
                self.backward_bulk_start_tmp = packet.time
                self.backward_bulk_last_timestamp = packet.time
                self.backward_bulk_count_tmp = 1
                self.backward_bulk_size_tmp = payload_size
            else:
                if (
                        packet.time - self.backward_bulk_last_timestamp
                ) > CLUMP_TIMEOUT:
                    self.backward_bulk_start_tmp = packet.time
                    self.backward_bulk_last_timestamp = packet.time
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
                                packet.time - self.backward_bulk_start_tmp
                        )
                    elif self.backward_bulk_count_tmp > BULK_BOUND:
                        self.backward_bulk_packet_count += 1
                        self.backward_bulk_size += payload_size
                        self.backward_bulk_duration += (
                                packet.time - self.backward_bulk_last_timestamp
                        )
                    self.backward_bulk_last_timestamp = packet.time

    def _get_duration(self):
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
            "dst_port": self.dst_port,
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "protocol": self.protocol,

            # Basic information from packet times
            "timestamp": packet_time.get_time_stamp(),
            "flow_duration": 1e6 * packet_time.get_duration(),
            "flow_byts_s": flow_bytes.get_rate(),
            "flow_pkts_s": packet_count.get_rate(),
            "fwd_pkts_s": packet_count.get_rate(PacketDirection.FORWARD),
            "bwd_pkts_s": packet_count.get_rate(PacketDirection.REVERSE),

            # Count total packets by direction
            "tot_fwd_pkts": packet_count.get_total(PacketDirection.FORWARD),
            "tot_bwd_pkts": packet_count.get_total(PacketDirection.REVERSE),

            # Statistical info obtained from Packet lengths
            "totlen_fwd_pkts": packet_length.get_total(PacketDirection.FORWARD),
            "totlen_bwd_pkts": packet_length.get_total(PacketDirection.REVERSE),
            "fwd_pkt_len_max": float(packet_length.get_max(PacketDirection.FORWARD)),
            "fwd_pkt_len_min": float(packet_length.get_min(PacketDirection.FORWARD)),
            "fwd_pkt_len_mean": float(packet_length.get_mean(PacketDirection.FORWARD)),
            "fwd_pkt_len_std": float(packet_length.get_std(PacketDirection.FORWARD)),
            "bwd_pkt_len_max": float(packet_length.get_max(PacketDirection.REVERSE)),
            "bwd_pkt_len_min": float(packet_length.get_min(PacketDirection.REVERSE)),
            "bwd_pkt_len_mean": float(packet_length.get_mean(PacketDirection.REVERSE)),
            "bwd_pkt_len_std": float(packet_length.get_std(PacketDirection.REVERSE)),
            "pkt_len_max": packet_length.get_max(),
            "pkt_len_min": packet_length.get_min(),
            "pkt_len_mean": float(packet_length.get_mean()),
            "pkt_len_std": float(packet_length.get_std()),
            "pkt_len_var": float(packet_length.get_var()),
            "fwd_header_len": flow_bytes.get_forward_header_bytes(),
            "bwd_header_len": flow_bytes.get_reverse_header_bytes(),
            "fwd_seg_size_min": flow_bytes.get_min_forward_header_bytes(),
            "fwd_act_data_pkts": packet_count.has_payload(PacketDirection.FORWARD),

            # Flows Interarrival Time
            "flow_iat_mean": float(flow_iat["mean"]),
            "flow_iat_max": float(flow_iat["max"]),
            "flow_iat_min": float(flow_iat["min"]),
            "flow_iat_std": float(flow_iat["std"]),
            "fwd_iat_tot": forward_iat["total"],
            "fwd_iat_max": float(forward_iat["max"]),
            "fwd_iat_min": float(forward_iat["min"]),
            "fwd_iat_mean": float(forward_iat["mean"]),
            "fwd_iat_std": float(forward_iat["std"]),
            "bwd_iat_tot": float(backward_iat["total"]),
            "bwd_iat_max": float(backward_iat["max"]),
            "bwd_iat_min": float(backward_iat["min"]),
            "bwd_iat_mean": float(backward_iat["mean"]),
            "bwd_iat_std": float(backward_iat["std"]),

            # Flags statistics
            "fwd_psh_flags": flag_count.has_flag("PSH", PacketDirection.FORWARD),
            "bwd_psh_flags": flag_count.has_flag("PSH", PacketDirection.REVERSE),
            "fwd_urg_flags": flag_count.has_flag("URG", PacketDirection.FORWARD),
            "bwd_urg_flags": flag_count.has_flag("URG", PacketDirection.REVERSE),
            "fin_flag_cnt": flag_count.has_flag("FIN"),
            "syn_flag_cnt": flag_count.has_flag("SYN"),
            "rst_flag_cnt": flag_count.has_flag("RST"),
            "psh_flag_cnt": flag_count.has_flag("PSH"),
            "ack_flag_cnt": flag_count.has_flag("ACK"),
            "urg_flag_cnt": flag_count.has_flag("URG"),
            "ece_flag_cnt": flag_count.has_flag("ECE"),

            # Response Time
            "down_up_ratio": packet_count.get_down_up_ratio(),
            "pkt_size_avg": packet_length.get_avg(),
            "init_fwd_win_byts": self.init_window_size[PacketDirection.FORWARD],
            "init_bwd_win_byts": self.init_window_size[PacketDirection.REVERSE],
            "active_max": float(active_stat["max"]),
            "active_min": float(active_stat["min"]),
            "active_mean": float(active_stat["mean"]),
            "active_std": float(active_stat["std"]),
            "idle_max": float(idle_stat["max"]),
            "idle_min": float(idle_stat["min"]),
            "idle_mean": float(idle_stat["mean"]),
            "idle_std": float(idle_stat["std"]),
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
        data["fwd_seg_size_avg"] = data["fwd_pkt_len_mean"]
        data["bwd_seg_size_avg"] = data["bwd_pkt_len_mean"]
        data["cwe_flag_count"] = data["fwd_urg_flags"]
        data["subflow_fwd_pkts"] = data["tot_fwd_pkts"]
        data["subflow_bwd_pkts"] = data["tot_bwd_pkts"]
        data["subflow_fwd_byts"] = data["totlen_fwd_pkts"]
        data["subflow_bwd_byts"] = data["totlen_bwd_pkts"]

        return data
