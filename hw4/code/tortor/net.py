
import abc
from .exception import TortToarNetException
from .utils import log


class Node:
    """
    Network nodes
    """

    def __init__(self, ip):
        self.ip = ip
        self.netman = None

    @abc.abstractmethod
    def on_packet(self, payload, src_ip):
        """
        called when a packet is received at the node
        :param payload: bytes - received byte sequence
        :param src_ip: bytes - IP of packet's sender
        :return:
        """
        pass


class NetManager:
    """
    This is a dummy implementation of the NetManager class in the judge (which has
    the same interface). This class is used for sending packets amongst nodes.
    Each node (e.g. relays) should register on the netmanager before using it.
    """

    def __init__(self):
        self.nodes = dict()

    def register_node(self, node):

        if node.ip in self.nodes:
            raise TortToarNetException("IP address {} already registered.".format(node.ip))

        self.nodes[node.ip] = node
        node.netman = self

    def convey_packet(self, src_ip, dest_ip, payload):
        log("Conveying packet from {} to {} ({} bytes)".format(src_ip, dest_ip, len(payload)))
        self.nodes[dest_ip].on_packet(payload, src_ip)

    @property
    def current_time(self):
        """
        :return: network current time as an integer
        """
        return 1514282176




