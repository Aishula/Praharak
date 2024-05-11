import socket


class PacketCapture:
    def __init__(self, packet_analyzer, interface="wlp2s0"):
        self.packet_analyzer = packet_analyzer
        self.interface = interface

    def start_capture(self):
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) as raw_socket:
            raw_socket.bind((self.interface, 0))
            while True:
                try:
                    raw_data = raw_socket.recvfrom(65536)
                    self.packet_analyzer.analyze(raw_data)
                except KeyboardInterrupt:
                    print("\nTerminated by user.")
                    print("Exiting...")
                    break
                except Exception as e:
                    print("\nAn error occurred.")
                    print("Exiting...")
                    break
