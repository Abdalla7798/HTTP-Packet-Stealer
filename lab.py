import socket
import struct


class IpPacket(object):

    def __init__(self, protocol, ihl, source_address, destination_address, payload):
        self.protocol = protocol

        self.ihl = ihl

        self.source_address = source_address

        self.destination_address = destination_address

        self.payload = payload


class TcpPacket(object):

    def __init__(self, src_port, dst_port, data_offset, payload):
        self.src_port = src_port

        self.dst_port = dst_port

        # As far as I know, this field doesn't appear in Wireshark for some reason.

        self.data_offset = data_offset

        self.payload = payload


def parse_raw_ip_addr(raw_ip_addr: bytes) -> str:
    ip = struct.unpack('!4s', raw_ip_addr)
    return '.'.join(map(str, ip[0]))


def parse_application_layer_packet(ip_packet_payload: bytes) -> TcpPacket:
    tcph = struct.unpack('! H H L L H', ip_packet_payload[:14])
    src_port = tcph[0]
    dest_port = tcph[1]
    offset = (tcph[4] >> 12)
    payload = ip_packet_payload[offset*4:]

    return TcpPacket(src_port, dest_port, offset, payload)


def parse_network_layer_packet(ip_packet: bytes) -> IpPacket:
    ip_header = ip_packet[0:12]

    iph = struct.unpack('!BBHHHBBH', ip_header)

    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0xF)

    protocol = iph[6]

    s_addr = ip_packet[12:16]
    d_addr = ip_packet[16:20]

    src_ip = parse_raw_ip_addr(s_addr)
    des_ip = parse_raw_ip_addr(d_addr)

    payload = ip_packet[ihl*4:]

    return IpPacket(protocol, ihl, src_ip, des_ip, payload)


def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = s.recvfrom(4096)
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', raw_data[:14])

        if socket.htons(proto) == 8:
            ip_packet = raw_data[14:]
            ip_packet_obj = parse_network_layer_packet(ip_packet)
            if ip_packet_obj.protocol == 6:
                tcp_packet_obj = parse_application_layer_packet(ip_packet_obj.payload)
                try:
                    if tcp_packet_obj.dst_port == 80 or tcp_packet_obj.src_port == 80:
                        data = tcp_packet_obj.payload.decode('utf-8')
                        print('\nIP Header Length : ' + str(ip_packet_obj.ihl) +
                              '\nProtocol : ' + str(ip_packet_obj.protocol) +
                              '\nSource Address : ' + str(ip_packet_obj.source_address) +
                              '\nDestination Address : ' + str(ip_packet_obj.destination_address),
                              end="")

                        print('\nSource Port : ' + str(tcp_packet_obj.src_port) +
                              '\nDest Port : ' + str(tcp_packet_obj.dst_port) +
                              '\nTCP header offset: ' + str(tcp_packet_obj.data_offset) +
                              '\n')

                        print(data)
                except:
                    print("None")


if __name__ == "__main__":
    main()


