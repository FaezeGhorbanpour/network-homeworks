import dpkt
import sys
import socket
from dpkt.compat import compat_ord


def mac_addr(address):
    return ':'.join('%02x' % compat_ord(b) for b in address)

def ip_addr(address):
    return '.'.join(str(int(b,16)) for b in address)

def ByteToHex(byteStr):
    return ''.join(["%02X " % ord(x) for x in byteStr])

def inet_to_str(inet):
    return socket.inet_ntoa(inet)

def hex_to_decimal(hex_array, end, first):
    number = 0
    for hex_index in range(end, first, -1):
        n = int(hex_array[hex_index], 16)
        number += n * 16 ** (end - hex_index)
    return number


f = open(sys.argv[1], 'rb')
pcap = dpkt.pcap.Reader(f)
i = 0
list_of_routers = set()
dict_router_lsa = dict()
for timestamp, buf in pcap:
    # print 'Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp))
    i += 1
    eth = dpkt.ethernet.Ethernet(buf)
    # print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)
    if not isinstance(eth.data, dpkt.ip.IP):
        # print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
        continue
    ip = eth.data

    if isinstance(ip.data, dpkt.ospf.OSPF):
        ospf = ip.data
        if ospf.type == 4:
            source_ospf_router = ospf.router
            ospf_hex = ByteToHex(ospf.data).split(' ')
            ospf_length = ospf.len
            base = 0

            number_of_lsas = hex_to_decimal(ospf_hex, 3, -1)
            base += 4
            for lsa_index in range(number_of_lsas):
                lsa_length = hex_to_decimal(ospf_hex, base + 19, base + 17)
                lsa_link_state_id = hex_to_decimal(ospf_hex, base + 8, base + 4)#ip_addr(ospf_hex[base+4:base+8])
                if lsa_length > 32:
                    list_of_routers.add(lsa_link_state_id)
                    dict_router_lsa[lsa_link_state_id] = set()
                    number_of_links = hex_to_decimal(ospf_hex, base + 23, base + 21 )
                    link_base = base + 24
                    for link_index in range(number_of_links):
                        link_id = ip_addr(ospf_hex[link_base: link_base+3])# hex_to_decimal(ospf_hex, link_base + 3, link_base )
                        dict_router_lsa[lsa_link_state_id].add(link_id)
                        link_base += 12

                base += lsa_length


result_matrix = [[0 for j in range(len(list_of_routers))] for i in range(len(list_of_routers))]
sorted_link_of_routers = sorted(list_of_routers)
i = -1
for first_router in sorted_link_of_routers:
    j = -1
    i += 1
    for second_router in sorted_link_of_routers:
        j += 1
        if first_router != second_router:
            intersect = dict_router_lsa[first_router].intersection(dict_router_lsa[second_router])
            if intersect != set():
                result_matrix[i][j] = 1

with open('adjacent_matrix.txt', 'w') as f:
    for i in result_matrix:
        for j in i[:-1]:
            f.write(str(j) + ',')
        f.write(str(i[-1]))
        if i != result_matrix[-1]:
            f.write('\n')
    f.close()
