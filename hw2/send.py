#!/usr/bin/python
import random
import sys, os, time, math
from tcp import tcp
from thread import start_new_thread

if len(sys.argv) < 6:
    print("entry arguments is not correct")
    sys.exit(1)

# initialize given variables
sender_port = int(sys.argv[1])
receiver_port = int(sys.argv[2])
init_rtt = int(sys.argv[3])
max_window = int(sys.argv[4])
file_path = sys.argv[5]

# make pipe files
read_data_path = "./pipes/sender_" + sys.argv[1] + "_data.pipe"
os.mkfifo(read_data_path)
read_time_path = "./pipes/sender_" + sys.argv[1] + "_time.pipe"
os.mkfifo(read_time_path)

# define read or write files
def wait_for_reciever():
    global find_reciever
    base_time = time.time()
    while time.time() - base_time < 50:
        continue
    if not find_reciever:
        print 'sending host {0}: no receiving host {1} is available. '.format(sender_port, receiver_port)
        exit()


find_reciever = False
start_new_thread(wait_for_reciever,())
read_data_pipe = open(read_data_path, 'rb')
find_reciever = True
read_time_pipe = open(read_time_path, 'r')
write_data_path = "./pipes/netforward_data.pipe"
write_data_pipe = open(write_data_path, 'wb')



def calculateRTT():
    global previousEstimateRTT, sampleRTT
    if len(receiving_times) == 0:
        sampleRTT = int(init_rtt)
    else:
        last_rtt = max(receiving_times.keys())
        sampleRTT = (receiving_times[last_rtt] - sending_times[last_rtt]) / 2

    previousEstimateRTT = math.ceil(0.875 * previousEstimateRTT + 0.125 * sampleRTT)
    return previousEstimateRTT


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


def read_data_file():
    global received_packet, has_packet
    while True:
        data_size = read_data_pipe.read(4)
        if len(data_size) != 0:
            size = ((ord(data_size[0]) * 256 +ord(data_size[1])) * 256 + ord(data_size[2])) * 256 + ord(data_size[3])
            new_packet = read_data_pipe.read(int(size))
            received_packet = tcp()
            received_packet.decode_packet(new_packet)
            has_packet = True


def read_time_file():
    global global_time, state
    while True:
        tick = read_time_pipe.read(4)
        if len(tick) != 0:
                global_time += 1



# read file that we want to send it
whole_data = [' ',]
with open(file_path, 'rb') as file:
    file_content = file.read()
whole_data.extend([file_content[i:i+max_window] for i in range(0, len(file_content), max_window)])


last_byte_recieved_ack = 0
last_sended_byte = 0
base_number = random.randint(0, 1000)

number_of_last_ack = 0
is_timeOut = False
middle_windows_size = 0
has_packet = False
received_packet = None
global_time = -1
end_file = False
is_state_5 = False
is_state_4 = False


# thread
start_new_thread(read_data_file,())
start_new_thread(read_time_file,())

# Timeout
calculated_rtt_times = dict()
sending_times = dict()
receiving_times = dict()
previousEstimateRTT = 10
sampleRTT = int(init_rtt)
receive_correct_ack = True
ack_not_received = False

while global_time < 0:
    pass

state = 1
while True:
    if state == 1:
        # print 'state 1'
        print 'sending host {}: is running . . . '.format(sender_port)
        packet = tcp()
        packet.source = int(sender_port)
        packet.dest = int(receiver_port)
        packet.syn = 1
        packet.seq = base_number
        syn_packet = packet.make_packet_no_data()
        calculated_rtt_times[0] = 2 * calculateRTT()
        sending_times[0] = global_time
        send_packet(syn_packet)
        state = 2

    elif state == 2:
        if global_time - sending_times[0] > calculated_rtt_times[0]:
            state = 1
        if has_packet and received_packet.syn == 1 and received_packet.ack == 1:
            # print 'state 2'
            has_packet = False
            if received_packet.syn == 1 and received_packet.ack == 1:
                receiving_times[0] = global_time
                packet = tcp()
                packet.source = int(sender_port)
                packet.dest = int(receiver_port)
                packet.ack = 1
                packet.seq = base_number
                ack_packet = packet.make_packet_no_data()
                send_packet(ack_packet)
                state = 3
            else:
                state = 1
    elif state == 3:
        # print 'state 3'
        packet = tcp()
        packet.source = int(sender_port)
        packet.dest = int(receiver_port)
        last_sended_byte += 1
        packet.seq = base_number + last_sended_byte
        packet.windows_size = last_sended_byte - last_byte_recieved_ack
        data_packet = packet.make_packet_with_data(whole_data[last_sended_byte])
        calculated_rtt_times[last_sended_byte] = 2 * calculateRTT()
        # print  ' number ' + str(last_sended_byte) + 'sended '
        sending_times[last_sended_byte] = global_time
        send_packet(data_packet)
        # print sending_times, calculated_rtt_times, receiving_times
        state = 4

    # exponinatial growing
    elif state == 4:
        if has_packet and received_packet.ack == 1 and received_packet.syn == 0:
            is_state_4 = True
            # print 'state 4'
            has_packet = False
            ack = int(received_packet.ack_seq) - int(base_number)
            if ack - 2 == max(receiving_times.keys()):
                receiving_times[ack - 1] = global_time
                number_of_last_ack = 0
                last_byte_recieved_ack += 1
                receive_correct_ack = True
            elif ack - 1 == max(receiving_times.keys()):
                number_of_last_ack += 1
            elif ack - 1 > max(receiving_times.keys()):
                for i in range(max(receiving_times) + 1, min(max(sending_times), ack - 1) + 1):
                    receiving_times[i] = global_time
                    receive_correct_ack = True

            if not end_file:
                for i in range(2):
                    if last_sended_byte + 1 < len(whole_data):
                        packet = tcp()
                        packet.source = sender_port
                        packet.dest = receiver_port
                        last_sended_byte += 1
                        packet.seq = base_number + last_sended_byte
                        packet.windows_size = last_sended_byte - last_byte_recieved_ack
                        data_packet = packet.make_packet_with_data(whole_data[last_sended_byte])
                        calculated_rtt_times[last_sended_byte] = 2 * calculateRTT()
                        # print  ' number ' + str(last_sended_byte) +'sended'
                        sending_times[last_sended_byte] = global_time
                        send_packet(data_packet)

            if is_timeOut and last_sended_byte - last_byte_recieved_ack == middle_windows_size :
                state = 5
                linear_base = last_sended_byte
                is_timeOut = False

            # print sending_times, calculated_rtt_times, receiving_times
    elif state == 5:
        if has_packet:
            # print 'state 5'
            has_packet = False
            is_state_5 = True
            ack = int(received_packet.ack_seq) - int(base_number)
            if ack - 2 == max(receiving_times.keys()):
                receiving_times[ack - 1] = global_time
                number_of_last_ack = 0
                last_byte_recieved_ack += 1
                receive_correct_ack = True
            elif ack - 1 == max(receiving_times.keys()):
                number_of_last_ack += 1
            elif ack - 1 > max(receiving_times.keys()):
                for i in range(max(receiving_times) + 1, min(max(sending_times) , ack - 1) + 1):
                    receiving_times[i] = global_time
                    receive_correct_ack = True

            j = 1
            if (last_sended_byte - linear_base) % 4 == 3:
                j = 2

            if not end_file and receive_correct_ack:
                for i in range(j):
                    packet = tcp()
                    packet.source = sender_port
                    packet.dest = receiver_port
                    last_sended_byte += 1
                    packet.seq = base_number + last_sended_byte
                    packet.windows_size = last_sended_byte - last_byte_recieved_ack
                    # print sending_times, calculated_rtt_times, receiving_times
                    data_packet = packet.make_packet_with_data(whole_data[last_sended_byte])
                    calculated_rtt_times[last_sended_byte] = 2 * calculateRTT()
                    # print  ' number ' + str(last_sended_byte) + 'sended'
                    sending_times[last_sended_byte] = global_time
                    send_packet(data_packet)

            # print sending_times, calculated_rtt_times, receiving_times

    elif state == 6:
        # print 'state 6'
        fin_tcp = tcp()
        fin_tcp.fin = 1
        fin_packet = fin_tcp.make_packet_no_data()
        send_packet(fin_packet)
        sending_times['fin'] = global_time
        calculated_rtt_times['fin'] = 2 * calculateRTT()
        state = 7

    elif state == 7:
        if has_packet:
            # print 'state 7'
            has_packet = False
            if received_packet.ack == 1:
                state = 8

        if global_time - sending_times['fin'] > calculated_rtt_times['fin']:
            state = 6

    elif state == 8:
        if has_packet:
            # print 'state 8'
            has_packet = False
            if received_packet.fin == 1:
                new_tcp = tcp()
                new_tcp.source = sender_port
                new_tcp.dest = receiver_port
                new_tcp.ack = 1
                packet = new_tcp.make_packet_no_data()
                send_packet(packet)
                print 'sending hos {}: is terminated.'.format(sender_port)
                time.sleep(15)
                exit()

    if state == 4 or state == 5:

        #check time out
        for i in range(max(receiving_times.keys()) + 1, max(sending_times.keys()) + 1):
            if global_time - sending_times[i] > calculated_rtt_times[i] and receive_correct_ack:
                # print 'time out happened !! ', global_time , sending_times , calculated_rtt_times, receiving_times
                is_timeOut = True
                middle_windows_size = math.floor((last_sended_byte- last_byte_recieved_ack ) / 2)
                if middle_windows_size < 1:
                    middle_windows_size = 1
                state = 3
                last_sended_byte = i - 1
                sending_times = {j:sending_times[j] for j in sending_times.keys() if j < i}
                calculated_rtt_times = {j:calculated_rtt_times[j] for j in calculated_rtt_times.keys() if j < i}
                break

        # check end of file
        if max(receiving_times.keys()) == len(whole_data) - 1:
            state = 6

        if last_sended_byte + 1 >= len(whole_data):
            end_file = True
        else:
            end_file = False

                # age tedad ack ha beshtar az 3 bashe
        if number_of_last_ack > 3 and not end_file and receive_correct_ack and is_timeOut:
            # print 'duplicate ack happened !!'

            receive_correct_ack = False
            temp_packet = last_byte_recieved_ack + 1
            last_sended_byte = last_byte_recieved_ack + (last_sended_byte - last_byte_recieved_ack) / 2
            sending_times = {j:sending_times[j] for j in sending_times.keys() if j <= last_sended_byte}
            calculated_rtt_times = {j:calculated_rtt_times[j] for j in calculated_rtt_times.keys() if j <= last_sended_byte}
            linear_base = last_sended_byte
            packet = tcp()
            packet.source = sender_port
            packet.dest = receiver_port
            packet.seq = base_number + temp_packet
            packet.windows_size = last_sended_byte - last_byte_recieved_ack
            data_packet = packet.make_packet_with_data(whole_data[temp_packet])
            calculated_rtt_times[temp_packet] = 2 * calculateRTT()
            sending_times[temp_packet] = global_time
            send_packet(data_packet)
            number_of_last_ack = 0
            state = 5
            # print temp_packet, sending_times[temp_packet], calculated_rtt_times[temp_packet]
            # print global_time, sending_times, calculated_rtt_times, receiving_times

    if last_byte_recieved_ack - last_sended_byte >= max_window:
        state = 5
        linear_base = last_sended_byte