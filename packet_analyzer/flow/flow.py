from datetime import datetime, timezone


class Flow:
    """
    Flow class for representing a flow in the network.
    """
    def __init__(self, flow_id):
        self.flow_id = flow_id
        self.packets = []
        self.start_time = datetime.now(timezone.utc)
        self.end_time = None
        self.fwd_packets = []
        self.bwd_packets = []
        self.total_fwd_packets = 0
        self.total_bwd_packets = 0
        self.fwd_packet_lengths = []
        self.bwd_packet_lengths = []
        self.fwd_iat = []
        self.bwd_iat = []
        self.prev_fwd_packet_time = None
        self.prev_bwd_packet_time = None

    def add_packet(self, packet, direction):
        """
        Add packet to the flow and update statistics
        :param packet:
        :return:
        """
        current_time = datetime.now(timezone.utc)
        packet_length = len(packet["raw_data"])

        if direction == "forward":
            self.fwd_packets.append(packet)
            self.total_fwd_packets += 1
            self.fwd_packet_lengths.append(packet_length)
            if self.prev_fwd_packet_time is not None:
                self.fwd_iat.append((current_time - self.prev_fwd_packet_time).total_seconds())
            self.prev_fwd_packet_time = current_time
        else:
            self.bwd_packets.append(packet)
            self.total_bwd_packets += 1
            self.bwd_packet_lengths.append(packet_length)
            if self.prev_bwd_packet_time is not None:
                self.bwd_iat.append((current_time - self.prev_bwd_packet_time).total_seconds())
            self.prev_bwd_packet_time = current_time

    def is_expired(self, expiration_threshold):
        """
        Check if the flow is expired
        :param expiration_threshold:
        :return: Boolean
        """
        if self.end_time is None:
            return True
        elif (datetime.now() - self.end_time).total_seconds() > expiration_threshold:
            return True
        else:
            return False

    def _get_duration(self):
        """
        Get the duration of the flow
        :return: Duration in seconds
        """
        if self.end_time is None:
            self.end_time = datetime.now()
        return (self.end_time - self.start_time).total_seconds()

    def get_features(self):
        """
        Calculate and return the statistical features of the flow
        :return: Dictionary
        """
        duration = self._get_duration()
        packet_count = len(self.packets)
        print({
            "duration": duration,
            "packet_count": packet_count
        })
        return {
            "duration": duration,
            "packet_count": packet_count
        }
