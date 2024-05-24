from datetime import datetime, timezone
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
                    raw_data, addr = raw_socket.recvfrom(65536)
                    byte_data = addr[4]
                    timestamp_ms = int.from_bytes(byte_data, byteorder='big')
                    timestamp = datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc)
                    self.packet_analyzer.analyze(raw_data, timestamp)

                except KeyboardInterrupt:
                    print("\nTerminated by user.")
                    print("Exiting...")
                    break
                except Exception as e:
                    print("\nAn error occurred.", e)
                    print("Exiting...")
                    break
