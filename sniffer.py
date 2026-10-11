import queue
import time
from scapy.all import AsyncSniffer

class PacketSniffer:
    def __init__(self, packet_queue):
        self.queue = packet_queue
        self.sniffer = None
        self.iface = None
        self.dropped_packets = 0
        self.sniffed_packets = 0

        self.last_packet_count = 0
        self.last_pps_time = time.monotonic()

    def handle_packet(self, pkt):
        self.sniffed_packets += 1
        try:
            self.queue.put_nowait(pkt)

        except queue.Full:
            self.dropped_packets += 1

    def get_pps(self):
        now = time.monotonic()
        elapsed = now - self.last_pps_time

        packets_since_last = (
            self.sniffed_packets - self.last_packet_count
        )
        pps = packets_since_last / elapsed if elapsed > 0 else 0

        self.last_packet_count = self.sniffed_packets
        self.last_pps_time = now

        return pps

    def start(self, iface, bpf_filter=None):
        if self.is_running():
            return

        self.sniffer = AsyncSniffer(
            iface=iface,
            filter=bpf_filter,
            prn=self.handle_packet,
            store=False
        )

        self.sniffer.start()

    def stop(self):
        if self.sniffer and self.sniffer.running:
            self.sniffer.stop()


    def is_running(self):

        # Checks if sniffer is curretly running
        return (
            self.sniffer is not None
            and self.sniffer.running
        )
