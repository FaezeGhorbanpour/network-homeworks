#! /usr/bin/python



import sys
import os

from tcp import tcp

if len(sys.argv) < 2:
    print("Usage: ./receive.py <port>")
    sys.exit(1)



# make pipe files
port = int(sys.argv[1])
read_data_path = "./pipes/receiver_" + str(port) +"_data.pipe"
os.mkfifo(read_data_path)

# define read or write files
read_data_pipe = open(read_data_path, 'rb')
write_data_path = "./pipes/netbackward_data.pipe"
write_data_pipe = open(write_data_path, 'wb')


def send_packet(data):
    l = len(data)
    x0 = l % 256
    l = l // 256
    x1 = l % 256
    l = l // 256
    x2 = l % 256
    l = l // 256
    x3 = l
    if x3 >= 256:
        raise Exception('Very large buffer')

    write_data_pipe.write(bytearray([x3, x2, x1, x0]))
    write_data_pipe.write(bytearray(data))
    write_data_pipe.flush()


data = dict()
base_number = 0
state = 0
print 'receiving host {}: is running . . .'.format(port)
while True:
    data_size = read_data_pipe.read(4)
    if len(data_size) != 0:
        size = size = ((ord(data_size[0]) * 256 +ord( data_size[1])) * 256 + ord(data_size[2])) * 256 + ord(data_size[3])
        new_packet = read_data_pipe.read(int(size))


        received_packet = tcp()
        received_packet.decode_packet(new_packet)
        dest_port = received_packet.source
        source_port = received_packet.dest

        if received_packet.syn == 1 and received_packet.ack == 0:
            base_number = int(received_packet.seq)
            new_tcp = tcp()
            new_tcp.source = int(source_port)
            new_tcp.dest = int(dest_port)
            new_tcp.syn = 1
            new_tcp.ack = 1
            new_packet = new_tcp.make_packet_no_data()
            send_packet(new_packet)
        elif received_packet.syn == 0 and received_packet.ack == 1 and int(received_packet.seq )== base_number :
            # print 'ready to receive data !'
            state = 1

        elif received_packet.fin == 1:
            new_tcp = tcp()
            new_tcp.source = int(source_port)
            new_tcp.dest = int(dest_port)
            new_tcp.ack = 1
            new_packet = new_tcp.make_packet_no_data()
            send_packet(new_packet)

            new_tcp = tcp()
            new_tcp.source = int(source_port)
            new_tcp.dest = int(dest_port)
            new_tcp.fin = 1
            new_packet = new_tcp.make_packet_no_data()
            send_packet(new_packet)
            state = 2

        elif received_packet.ack == 1 and state == 2:
            print 'receiving host {}: is terminated.'.format(port)
            data_string = ''
            for i in range(1, max(data.keys()) + 1):
                data_string += data[i]
            # print data_string
            exit()
        else:
            if state == 1:
                data[int(received_packet.seq) - int(base_number)] = received_packet.data
                # print 'received data is {0}'.format(data)
                j = max(data.keys())+1
                for i in range(1,len(data)*5):
                    if i not in data.keys():
                        j = i
                        break
                new_tcp = tcp()
                new_tcp.source = int(source_port)
                new_tcp.dest = int(dest_port)
                # print 'ack with ack_seq ' + str(base_number + j) + ' sended'
                new_tcp.ack_seq = base_number + j
                new_tcp.ack = 1
                new_packet = new_tcp.make_packet_no_data()
                send_packet(new_packet)