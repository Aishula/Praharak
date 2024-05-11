import socket


class PacketCapture:
    def __init__(self, packet_analyzer):
        self.packet_analyzer = packet_analyzer

    def start_capture(self):
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) as raw_socket:
            raw_socket.bind(("wlp2s0", 0))
            while True:
                raw_data = raw_socket.recvfrom(65536)
                self.packet_analyzer.analyze(raw_data)
