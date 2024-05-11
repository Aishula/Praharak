class PacketAnalyzer:
    def __init__(self, packet_handler):
        self.packet_handler = packet_handler

    def analyze(self, raw_data):
        print(raw_data)

    def extract_features(self, packet_data):
        pass
