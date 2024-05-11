import os
import sys

from packet_capture import PacketCapture
from packet_analyzer import PacketAnalyzer
from packet_handler import PacketHandler


def main():
    packet_handler = PacketHandler()
    packet_analyzer = PacketAnalyzer(packet_handler)
    packet = PacketCapture(packet_analyzer)
    packet.start_capture()


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Error: This program must be run with superuser privileges.")
        sys.exit(1)
    main()
