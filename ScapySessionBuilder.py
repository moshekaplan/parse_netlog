from scapy.all import *

class UDPSessionBuilder:
    def __init__(self, client_ip, server_ip, client_port, server_port, client_seq=1000, server_seq=20000, ipv4=True):
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.client_port = client_port
        self.server_port = server_port
        self.ipv4 = ipv4
        self.packets = []

    def _ip_layer(self, src, dst):
        if self.ipv4:
            return IP(src=src, dst=dst)
        else:
            return IPv6(src=src, dst=dst)

    def _build(self, src, dst, sport, dport, payload=b""):
        ip = self._ip_layer(src, dst)
        return ip / \
               UDP(sport=sport, dport=dport) / \
               payload

    def add_client_payload(self, payload):
        pkt = self._build(self.client_ip, self.server_ip, self.client_port, self.server_port,
                          payload)
        self.packets.append(pkt)
        return pkt

    def add_server_payload(self, payload):
        pkt = self._build(self.server_ip, self.client_ip, self.server_port, self.client_port,
                          payload)
        self.packets.append(pkt)
        return pkt

    def save(self, filename="udp_session.pcap"):
        wrpcap(filename, self.packets)


class TCPSessionBuilder:
    def __init__(self, client_ip, server_ip, client_port, server_port, client_seq=1000, server_seq=20000, ipv4=True):
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.client_port = client_port
        self.server_port = server_port
        self.client_seq = client_seq
        self.server_seq = server_seq
        self.ipv4 = ipv4
        self.packets = []

    def _ip_layer(self, src, dst):
        if self.ipv4:
            return IP(src=src, dst=dst)
        else:
            return IPv6(src=src, dst=dst)

    def _build(self, src, dst, sport, dport, flags, seq, ack, payload=b""):
        ip = self._ip_layer(src, dst)
        return ip / \
               TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack) / \
               payload

    def add_handshake(self):
        self.packets.append(
            self._build(self.client_ip, self.server_ip, self.client_port, self.server_port, "S", self.client_seq, 0)
        )
        self.packets.append(
            self._build(self.server_ip, self.client_ip, self.server_port, self.client_port, "SA",
                        self.server_seq, self.client_seq + 1)
        )
        self.packets.append(
            self._build(self.client_ip, self.server_ip, self.client_port, self.server_port, "A",
                        self.client_seq + 1, self.server_seq + 1)
        )
        self.client_seq += 1
        self.server_seq += 1

    def add_client_payload(self, payload):
        pkt = self._build(self.client_ip, self.server_ip, self.client_port, self.server_port,
                          "PA", self.client_seq, self.server_seq, payload)
        self.packets.append(pkt)
        self.client_seq += len(payload)
        return pkt

    def add_server_payload(self, payload):
        pkt = self._build(self.server_ip, self.client_ip, self.server_port, self.client_port,
                          "PA", self.server_seq, self.client_seq, payload)
        self.packets.append(pkt)
        self.server_seq += len(payload)
        return pkt

    def close_session(self):
        packets = []
        packets.append(
            self._build(self.client_ip, self.server_ip, self.client_port, self.server_port, "F",
                        self.client_seq, self.server_seq)
        )
        packets.append(
            self._build(self.server_ip, self.client_ip, self.server_port, self.client_port, "FA",
                        self.server_seq, self.client_seq + 1)
        )
        packets.append(
            self._build(self.client_ip, self.server_ip, self.client_port, self.server_port, "A",
                        self.client_seq + 1, self.server_seq + 1)
        )
        self.packets.extend(packets)
        return packets

    def save(self, filename="tcp_session.pcap"):
        wrpcap(filename, self.packets)
