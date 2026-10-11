from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello
from scapy.layers.dhcp import DHCP
from scapy.layers.ntp import NTP


class PacketParser:

    # Summarized view of packet used for overview of captured packets

    def summarize(self, packet):
        result = {
            "source": "",
            "destination": "",
            "protocol": "Unknown",
            "length": len(packet)
        }

        if IP in packet:
            result["source"] = packet[IP].src
            result["destination"] = packet[IP].dst

        elif IPv6 in packet:
            result["source"] = packet[IPv6].src
            result["destination"] = packet[IPv6].dst

        if TCP in packet:
            result["protocol"] = self.decode_tcp(packet)

        elif UDP in packet:
            result["protocol"] = self.decode_udp(packet)

        elif ARP in packet:
            result["protocol"] = "ARP"
            result["source"] = packet[ARP].psrc
            result["destination"] = packet[ARP].pdst

        elif ICMP in packet:
            result["protocol"] = "ICMP"

        return result

    def decode_tcp(self, packet):
            
            tcp = packet[TCP]

            result = "TCP"

            if HTTPRequest in packet:
                result = "HTTP Request"

            elif HTTPResponse in packet:
                result = "HTTP Response"

            elif TLSClientHello in packet:
                result = "TLS ClientHello"

            elif TLSServerHello in packet:
                result = "TLS ServerHello"

            elif TLS in packet:
                result = "TLS"

            elif 443 in (tcp.sport, tcp.dport):
                result = "TCP (443)"

            elif 80 in (tcp.sport, tcp.dport):
                result = "TCP (80)"

            return result

    def decode_udp(self, packet):
            udp = packet[UDP]

            result = "UDP"

            if DNS in packet:
                dns = packet[DNS]

                if dns.qr == 0:
                    result = "DNS Query"
                else:
                    result = "DNS Response"

            elif DHCP in packet:
                result = "DHCP"

            elif NTP in packet:
                result = "NTP"

            elif 443 in (udp.sport, udp.dport):
                result = "UDP (443, possible QUIC)"

            elif 5353 in (udp.sport, udp.dport):
                result = "mDNS (likely)"

            elif 1900 in (udp.sport, udp.dport):
                result = "SSDP (likely)"

            elif 3478 in (udp.sport, udp.dport):
                result = "STUN (likely)"

            elif 161 in (udp.sport, udp.dport):
                result = "SNMP (likely)"

            elif 162 in (udp.sport, udp.dport):
                result = "SNMP Trap (likely)"

            return result

    def detailed(self, packet):
        # Detailed parsing of packet used for inspecting a packet

        result = {}
        layer = packet

        while layer:
            result[layer.name] = {
                key: str(value) for key, value in layer.fields.items()
            }

            layer = layer.payload

            if not layer:
                break

        return result
        