from socket import *
from lib import *
import _thread


def proceed(games, data, adr):
    game_id, move = move_struct.unpack_from(data, 0)
    if games.get(game_id, None) is None:
        games[game_id] = []
    games[game_id].append((adr, move))
    if len(games[game_id]) == 2:
        adr = [games[game_id][0][0], games[game_id][1][0]]
        p = [games[game_id][0][1], games[game_id][1][1]]
        del games[game_id]
        res = [rps(p[0], p[1])]
        res.append(2 - res[0])
        ans_socket = socket(AF_INET, SOCK_DGRAM)
        ans_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        for i in [0, 1]:
            ans_socket.connect(adr[i])
            response = response_struct.pack(game_id, res[i])
            ans_socket.sendall(response)
        ans_socket.close()

judge = socket(AF_INET, SOCK_DGRAM)
judge.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
judge.bind(('', 22222))
games = {}
while True:
    data, adr = judge.recvfrom(512)
    _thread.start_new_thread(proceed, (games, data, adr))
