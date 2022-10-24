from socket import *
from lib import *
from pprint import pprint
from threading import *


class myThread (Thread):
    def __init__(self, so):
        super().__init__()
        self.so = so

    def run(self):
        data = self.so.recvfrom(512)
        self.so.close()
        game_id, res = response_struct.unpack_from(data[0], 0)

        print("{} game {}".format(states[res], game_id))


print("!!! Rock Paper Scissors Game !!!\n")
while True:
    pprint(moves)
    print("Enter your move and a game id")
    line = input()
    line = line.split()
    move = int(line[0])
    game_id = int(line[1])
    move = move_struct.pack(game_id, move)
    so = socket(AF_INET, SOCK_DGRAM)
    so.setsockopt(SOL_SOCKET, So_)
    so.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    so.sendto(move, ('', 22222))
    print("Your game and move have been reported, whenever ready, results will be shown to you.")
    thread = myThread(so)
    thread.start()
