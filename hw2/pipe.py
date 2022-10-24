#!/usr/bin/python

import sys, time


if len(sys.argv) < 3:
    print("Usage: ./pipe.py file1 file2 [file3]")
    sys.exit(1)

pipe_type = 'r' # receiver

FILE1 = "./pipes/" + sys.argv[1]
FILE2 = "./pipes/" + sys.argv[2]
FILE3 = "./pipes/"
if len(sys.argv) > 3:
    FILE3 = "./pipes/" + sys.argv[3]


f2 = open(FILE2, 'wb')
f3 = None 
if FILE3 != "./pipes/":
    f3 = open(FILE3, 'w')  
    pipe_type = 's' # sender

f1 = open(FILE1, 'rb')



#######################################################
def send_tick():
    if not f3:
        return
    f3.write("tick")
    f3.flush()
    print('tick')


def send_data(byte_list):
    l = len(byte_list)
    x0 = l % 256
    l = l // 256
    x1 = l % 256
    l = l // 256
    x2 = l % 256
    l = l // 256
    x3 = l
    if x3 >= 256:
        raise Exception('Very large buffer')

    f2.write(bytearray([x3, x2, x1, x0]))
    f2.write(bytearray(byte_list))
    f2.flush()


def handle_data(byte_list):
    while True:
        r = raw_input("new packet received. what to do? ")
        try:
            if not f3:
                pass
            else:
                x = r[1:]
                x = int(x)
                for i in range(x):
                    send_tick()
            
            if r[0] == 's':
                send_data(byte_list)
                return
            elif r[0] == 'd':
                return
        except:
            pass
        
        print("USAGE(forward): <d/s>NUM\tUSAGE(backward): <d/s>")

##############################################


if pipe_type == 's':
    send_tick()
while True:
    i = f1.read(4)
    if len(i) == 0:
        continue
    size = ((ord(i[0]) * 256 + ord(i[1])) * 256 + ord(i[2])) * 256 + ord(i[3])
    r = f1.read(int(size))
    if len(r) == 0:
        continue

    handle_data([x for x in r])