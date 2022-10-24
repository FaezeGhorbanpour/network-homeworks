import os
import struct
import rsa
import inspect
from rsa import PublicKey, PrivateKey
from .crypto import blob_rsa_dec, blob_rsa_enc
from .core import Relay

LOG_LEVEL = 4
PKEY_SERIALIZED_SIZE = 256


def find_all_paths(graph, start, end, visited_nodes,  path, all_path):
    visited_nodes[start] = True
    path.append(start)
    if start is not end:
        for i in graph.matrix[start]:
            if not visited_nodes[i] and len(path) < 6:
                find_all_paths(graph, i, end, visited_nodes, path, all_path)
    else:
        if len(path) > 3:
            all_path.append(list(path))
    path.pop()
    visited_nodes[start] = False


def encrypt_hobs(nodes, config):
    nodes_pk = [config.look_up_pk(ip) for ip in nodes]
    encrypt_nodes = b"".join([blob_rsa_enc(nodes[i + 1], nodes_pk[i]) for i in range(1, len(nodes) - 1)])
    encrypt_nodes += Relay.eoh(nodes_pk[-1])
    l = len(nodes)
    while l < 6:
        random_hob_ip = os.urandom(256)
        encrypt_nodes += random_hob_ip
        l += 1
    return encrypt_nodes


def bigint_to_bytes(i):
    """
    Serialize a large integer as network serialized bytes
    :param i:
    :return:
    """

    parts = []

    while i:
        parts.append(i & (2 ** 32 - 1))
        i >>= 32

    return struct.pack('>' + 32 * 'L', *parts)


def key_to_bytes(rsakey):
    """
    Convert rsa.PublicKey to its serialized bytes form
    :param rsakey: rsa.PublicKey
    :return: bytes
    """

    i = rsakey.n

    p1 = i & (2 ** 1024 - 1)
    p2 = i >> 1024

    return bigint_to_bytes(p1) + bigint_to_bytes(p2)


def bytes_to_key(mbytes):
    """
    Create rsa.PublicKey object from its serialized bytes form
    :param mbytes: bytes
    :return: rsa.PublicKey
    """

    parts = struct.unpack('>' + 64 * 'L', mbytes)

    res = 0
    for p in reversed(parts):
        res *= 2 ** 32
        res += p

    return PublicKey(res, 2 ** 16 + 1)


def log(*args, **kwargs):
    """
    Default log tool, whose use is highly recommended
    instead of the standard python "print" function

9    :param args: any - print args
    :param kwargs: dict - options
    """
    curframe = inspect.currentframe()
    calframe = inspect.getouterframes(curframe, 2)
    callername = calframe[1][3]
    if kwargs.get("level", 1) <= LOG_LEVEL:
        if not kwargs.get("omitcallername", False):
            print(callername + ":", *args)
        else:
            print(*args)


if __name__ == "__main__":
    a, b = rsa.newkeys(2048)
    print(a)
    s = key_to_bytes(a)
    r = bytes_to_key(s)
    print(r)
