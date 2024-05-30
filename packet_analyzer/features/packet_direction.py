from enum import Enum, auto


class PacketDirection(Enum):
    """
    Enum for packet direction
    """
    FORWARD = auto()
    REVERSE = auto()
