from datetime import datetime, timezone
import socket
from flow_session import FlowSession


class RawPacketCapture:
    """
    Responsible for capturing the raw packet in real time
    """
    def __init__(self, interface="wlp2s0"):
        self.interface = interface
        self.flow_session = FlowSession()

    def start_capture(self):
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) as raw_socket:
            raw_socket.bind((self.interface, 0))
            while True:
                try:
                    # Capture packet and send to flow session for processing
                    raw_data, addr = raw_socket.recvfrom(65536)
                    timestamp = datetime.now(timezone.utc)
                    self.flow_session.process_packet(raw_data, timestamp)

                except KeyboardInterrupt:
                    print("\nTerminated by user.")
                    print("Exiting...")
                    break
                except Exception as e:
                    print("\nAn error occurred.", e)
                    print("Exiting...")
                    break
