from collections import deque

class PacketStorage:
    def __init__(self):
        self.packets = deque(maxlen=5000)
        self.next_id = 0

    def save(self, summarized_packet, raw_packet):

        # Appends dict of important data of packet to self.packets
        packet = {
            "id": self.next_id,
            "summary": summarized_packet,
            "raw": raw_packet
        }

        self.packets.append(packet)
        self.next_id += 1

    def get_all(self):
        return self.packets

    def get_packet(self, packet_id):
        for packet in self.packets:
            if packet["id"] == packet_id:
                return packet

    def clear(self):
        self.packets.clear()


