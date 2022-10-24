#In The Name Of God
from socket import *

import thread, sys
import traceback

def get_domain(data):
    state = 0
    expected_length = 0
    domain_string = ''
    domain_part = []
    y = 0
    x = 0
    for byte in data:
        if state == 1:
            domain_string += chr(byte)
            if x == expected_length:
                domain_part.append(domain_string)
                domain_string = ''
                state = 0
                x = 0
            if byte == 0:
                domain_part.append(domain_string)
                break
        else:
            state = 1
            expected_length = byte
        x += 0
        y += 0
        question_type = data[y+1:y+3]
    return domain_part, question_type


def send_socket(data, ip, port):
    socket = socket(AF_INET, SOCK_DGRAM)
    socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    socket.sendto(data, (ip,port))
    return socket


def make_B_request(tid, data, address):
    flags = data[2:4]
    byte1 = bytes(flags[:1])
    byte2 = bytes(flags[1:])
    rflag = ''
    QR = '0'
    OPCODE = ''
    for bit in range(1,5):
        OPCODE += str(ord(byte1) & (1<<bit))
    AA = '1'
    TC = '0'
    RD = '0'
    RA = '0'
    Z = '0'
    state_message = str()
    if str(ord(byte1) & (1)) == '0' and OPCODE == '0000':
        state = -1
        state_message = 'REFUSED'
    else :
        state = 1
        state_message = 'NO ERROR'
    RCODE = '0000'
    flags = int(tid + QR + OPCODE + AA + TC + RD, 2).to_bytes(1, byteorder='big') + int(RA + Z + RCODE).to_bytes(1, byteorder='big')
    QDCOUNT = b'\x00' + b'\x01'
    ACOUNT = b'\x00' + b'\x00'
    Additional_Count =  b'\x00' + b'\x00'
    Authority_Count =  b'\x00' + b'\x00'

    string = 'connecting to ' + address + '\n'
    string += '=' * 15 + '\n'
    string += 'HEADER\n' + '=' * 15
    string += '{\n' + 'additinalo count : ' + str(Additional_Count[0])  + '\n' + 'answer count : ' + str(ACOUNT) + '\nid : ' + str(tid) + 'is authoritative : ' +  str(AA == '1')
    string += 'is response : ' + str(QR == '1') + 'is truncated : ' +str (TC == '1') + 'opcode : ' +  OPCODE + 'question count : ' + str(QDCOUNT[0])
    string += 'recursion available : ' + str(RA == '1') + 'recursion desired : ' +  str(RD == '1') + 'reserved : ' +str(Z==0) + 'response code : '  + state_message + '}'

    request = flags + QDCOUNT + QDCOUNT + ACOUNT + Authority_Count + Additional_Count
    return request, string, state


def make_D_request(tid, data, root):
    flags = data[2:4]
    byte1 = bytes(flags[:1])
    byte2 = bytes(flags[1:])
    QR = '1'
    OPCODE = ''
    for bit in range(1, 5):
        OPCODE += str(ord(byte1) & (1 << bit))
    AA = '1'
    TC = '0'
    RD = '0'
    RA = '0'
    Z = '0'
    RCODE = '0000'
    flags = int(tid + QR + OPCODE + AA + TC + RD, 2).to_bytes(1, byteorder='big') + int(RA + Z + RCODE).to_bytes(1,
                                                                                                                 byteorder='big')
    QDCOUNT = b'\x00' + b'\x01'
    domain_part, question_type= get_domain(data)
    at = ''
    if question_type == b'\x00\x01':
        qt = 'a'

    ACOUNT = b'\x00' + b'\x01'
    Additional_Count = b'\x00' + b'\x00'
    Authority_Count = b'\x00' + b'\x00'

    string = 'connecting to ' + address + '\n'
    string += '=' * 15 + '\n'
    string += 'HEADER\n' + '=' * 15
    string += '{\n' + 'additinalo count : ' + str(Additional_Count[0]) + '\n' + 'answer count : ' + str(
        ACOUNT) + '\nid : ' + str(tid) + 'is authoritative : ' + str(AA == '1')
    string += 'is response : ' + str(QR == '1') + 'is truncated : ' + str(
        TC == '1') + 'opcode : ' + OPCODE + 'question count : ' + str(QDCOUNT[0])
    string += 'recursion available : ' + str(RA == '1') + 'recursion desired : ' + str(RD == '1') + 'reserved : ' + str(
        Z == 0) + 'response code : ' + 'NO ERROR' + '}\n'
    string += '=' * 15 + "\n" + 'Qustions\n' + '='*15 + '\n'
    string += 'type : ' + qt
    string += str([domain for domain in domain_part])

    request = flags + QDCOUNT + QDCOUNT + ACOUNT + Authority_Count + Additional_Count
    return request, string


def dns_query(data, address, root):

    log = str()
    transaction_id = data[:2]
    tid = ''
    state = 1
    for byte in transaction_id:
        tid += int(byte,16)[2:0]

    while 1: # -1 : failed, 0 : success
        B_request, B_string, state = make_B_request(tid, data, root)
        socket = send_socket(B_request, root, 53)  
        log += B_string  

        #receive C request
        data, address = socket.recvfrom(512)

        #finind according ip if we find it, state become 0 and if failed to find it state become -1 and otherwise state is 1 and root address in ip we found
        address_domain = address.splite('.')
        domain, type = get_domain(data)
        if type == b'/x00/x01':
            if domain == address_domain:
                pass


        if state != -1 and state != 0:
            break

    if state == -1: #Failed
        send_socket(B_request, address, 53)
        log += B_string

    if state == 0:
        D_request, D_string = make_D_request(tid, data, root)
        send_socket(D_request, address, 53)
        log += D_string


    with open(str(transaction_id)+'.txt', 'w') as f:
        f.write(log)

if __name__ == "__main__":
    root = sys.argv[1]
    udp = socket(AF_INET, SOCK_DGRAM)
    udp.bind(('127.0.0.1',15353))  #TODO

    try:
        while 1:
            data, address = udp.recvfrom(512)
            print(data, address)
            thread.start_new_thread(dns_query, (data, address, root))
    except KeyboardInterrupt:
        print('Finish')
        udp.close()
    except:
        type, value, traceBack = sys.exc_info()
        lines = traceback.format_exception(type, value, traceBack)
        print(''.join('!! ' + line for line in lines))
        pass



