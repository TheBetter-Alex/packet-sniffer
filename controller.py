from scapy.utils import wrpcap
import queue

# Controls data flow from parser, storage, sniffer to the UI and each other
class PacketController:
    def __init__(self, sniffer, parser, storage, packet_queue):
        self.sniffer = sniffer
        self.parser = parser
        self.storage = storage
        self.packet_queue = packet_queue

    # Empties the queue and gives to parser and then saves in storage
    def process_queue(self):
        processed = 0
        while processed < 500:
            try:
                raw_packet = self.packet_queue.get_nowait()
            except queue.Empty:
                break
        
            try:
                summarized = self.parser.summarize(raw_packet)
                self.storage.save(summarized, raw_packet)
            except Exception as e:
                print(f"Packet processing error: {e}")

            processed += 1

    def get_packets(self):
        return self.storage.get_all()

    def get_packet_details(self, packet_id):
        packet = self.storage.get_packet(packet_id)

        if packet is None:
            return []

        return self.parser.detailed(packet["raw"])

    def get_packet(self, packet_id):
        return self.storage.get_packet(packet_id)

    def start_capture(self, iface, bpf_filter=None):
        self.sniffer.start(iface, bpf_filter)

    def stop_capture(self):
        self.sniffer.stop()

    def is_running(self):
        return self.sniffer.is_running()

    def get_pps(self):
        return self.sniffer.get_pps()

    def get_sniffed_count(self):
        return self.sniffer.sniffed_packets

    def get_dropped_count(self):
        return self.sniffer.dropped_packets

    def save_to_pcap(self, filename: str):

        all_packets = [
            packet["raw"] for packet in self.get_packets()
        ]
        wrpcap(filename, all_packets)
