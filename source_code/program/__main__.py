import os
import sys
import netifaces

from packet_capture import PacketCapture
from packet_analyzer import PacketAnalyzer
from packet_handler import PacketHandler


def list_network_interfaces():
    interfaces = netifaces.interfaces()
    print("Available network interfaces:")
    for interface in interfaces:
        print(f"---------> {interface}")


def main():
    list_network_interfaces()
    try:
        chosen_interface = input("Enter the name of the network interface to use: ")
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)

    packet_handler = PacketHandler()
    packet_analyzer = PacketAnalyzer(packet_handler)
    packet = PacketCapture(packet_analyzer)
    packet.start_capture()


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Error: You cannot perform this operation unless you are root.")
        sys.exit(1)
    main()
