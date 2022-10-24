from struct import Struct
moves = {
    0: 'Rock',
    1: 'Paper',
    2: 'Scissors'
}
states = {
    0: "lose",
    1: "draw",
    2: "win",
}


def rps(p1: int, p2: int) -> int:
    if p1 == p2:
        return 1
    if p2 == (p1+1) % 3:
        return 0
    return 2

move_struct = Struct('!HH')
response_struct = Struct('!HB')
