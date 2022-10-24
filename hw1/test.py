# # import random
# #
# # from tcp import tcp
# #
# # test_tcp = tcp()
# # test_tcp.source = 8080#00011111 10010000, 00000011 1110 1000
# # test_tcp.dest = 1000
# # test_tcp.ack = 1
# # test_tcp.syn = 1
# # packet = test_tcp.make_packet_with_data('hello world')
# # data_offset = format(ord(packet[12]), 'b')
# # data_offset = '0'*(8-len(data_offset)) + data_offset
# # doff = int(data_offset[0:4], 2)
# # data = ''
# # print packet[4*doff:]
# #
# # print data
# # print ' '.join(format(ord(x), 'b') for x in packet)
# max_window = 4
# with open("test.txt", 'rb') as file:
#     file_content = file.read()
# whole_data = [' ',]
# whole_data.extend([file_content[i:i+max_window] for i in range(0, len(file_content), max_window)])
# print whole_data
# #
from tcp import tcp

new_tcp = tcp()

new_tcp.source = 8080
new_tcp.dest = 1000
new_tcp.syn = 1
new_tcp.ack = 1
new_packet = new_tcp.make_packet_no_data()
print new_packet