"""
Responsible for capturing the raw packet in real time
"""
import os
import sys
import netifaces

from raw_packet_capture import RawPacketCapture


def list_network_interfaces():
    """
    List all available network interfaces
    """
    interfaces = netifaces.interfaces()
    print("Available network interfaces:")
    for interface in interfaces:
        print(f"->{interface}")


def main():
    list_network_interfaces()
    try:
        chosen_interface = input("Enter the name of the network interface to use: ")
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
    # Create RawPacketCapture object and start capturing
    packet = RawPacketCapture()
    packet.start_capture()


# Defining start point
if __name__ == "__main__":
    # Check if the user is superuser or not, if not, exit
    if os.geteuid() != 0:
        print("Error: You cannot perform this operation unless you are root.")
        sys.exit(1)
    main()
