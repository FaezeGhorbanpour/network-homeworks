# in the name of God

import heapq
import os

from collections import defaultdict

import math

from .net import Node
from .packet import Packet, URL_SIZE, Header, DataPacketBody, RegisterPacketBody
from rsa import decrypt, encrypt, VerificationError
from .exception import *
from .utils import *
from .crypto import blob_rsa_dec, blob_rsa_enc


class Graph:
    def __init__(self, number_of_nodes):
        self.number_of_nodes = number_of_nodes
        self.matrix = defaultdict(list)

    def addEdge(self, start, end):
        self.matrix[start].append(end)


class RelayAddress:
    """
    Information card for network nodes
    """

    def __init__(self, ip, pk):
        """
        :param ip: bytes
        :param pk: rsa.PublicKey
        """
        self.ip = ip
        self.pk = pk


class RelayConfig:
    def __init__(self, relay_list, net_graph):
        """
        The relay configuration object which contains a list
        of known public relays in addition to their network
        topology as a graph,
        :param relay_list: List<RelayAddress>
        :param net_graph: Set<Tuple<bytes (IP of node1), bytes (IP of node2), float (edge weight)>>
        """
        self.relay_list = relay_list
        self.net_graph = net_graph
        self.dist_map = dict([((n1, n2), d) for n1, n2, d in net_graph])

    def look_up_pk(self, ip):
        """
        returns public key of node with given IP address
        :param ip: bytes
        :return: rsa.PublicKey
        """
        for r in self.relay_list:
            if r.ip == ip:
                return r.pk

    def latency(self, n1, n2):
        return self.dist_map[(n1, n2)]

    def get_ip_country(self, ip):
        return ip.split(b".")[2]


class Relay(Node):
    def __init__(self, ip, pubkey, privkey, config, hidden_keypair=None):
        """
        :param ip: IP address of this node
        :param pubkey: rsa.PublicKey
        :param register: dict: return route of registered nodes on this relay as HH
        :param privkey: rsa.PrivateKey
        :param config: RelayConfig
        :param hidden_keypair: public-key and private-key of this node's hidden identity for deep web [optional]
        """
        super().__init__(ip)
        self.pubkey = pubkey
        self.privkey = privkey
        self.register = dict()
        self.config = config
        self.hidden_keypair = hidden_keypair

    @staticmethod
    def eoh(dest_pk):
        """
        The end of hops header bytes string encrypted for
        certain node
        :param dest_pk:
        :return:
        """
        return rsa.encrypt(b'0.0.0.0', dest_pk)

    def on_packet(self, payload, src_ip):
        """
        this gets called when the Relay receives a packet. Here,
        we parse the packet and decide whether we are the intended
        receiver or whether we should pass it along to another
        node in the TorToar network.

        :param payload: see parent class
        :param src_ip: see parent class
        :return: see parent class
        """

        # parse packet
        packet = Packet.from_bytes(payload, self.privkey) if not self.hidden_keypair \
            else Packet.from_bytes(payload, self.privkey, self.hidden_keypair[1])
        log("@", self.ip, "next hop =", packet.header.hops[0], level=4)
        next_hop_ip = decrypt(packet.header.hops[0], self.privkey)

        # decide whether packet targets us or another node
        if next_hop_ip == b"0.0.0.0":
            self.receive_packet(packet)
        else:
            self.relay_packet(packet, next_hop_ip)

    def relay_packet(self, packet, next_hop_ip):
        """
        Called on a packet that is not intended
        for current node. This method should update the
        packet header and pass it through the network.

        :param packet:
        :param next_hop_ip:
        :return:
        """
        random_hob_ip = os.urandom(256)
        changed_hobs = packet.header.hops[1:].append(random_hob_ip)
        changed_header = Header(packet.header.length, changed_hobs)
        packet_ = Packet(changed_header, packet.body)
        public_key = self.config.look_up_pk(next_hop_ip)
        self.netman.convey_packet(self.ip, next_hop_ip, packet_.to_bytes(public_key, None))

    def receive_packet(self, packet):
        """
        Called when a packet intended for current node is received. Keep in mind
        that the current node might be the hidden-handler and not the final node,
        but this method will be called all the same. Here, we shall check the
        body of the received packet, and act based on its type.

        Register packets: the hops should be kept in memory for the given hidden pubkey
        Data packet: the final destination must be checked. If the current node
                     is the FINAL receiver, self.on_data() should be called. otherwise,
                     a new packet must be created and sent through the registered
                     return hops to the final receiver.

        :param packet: Packet - received packet
        """
        body = packet.body
        if isinstance(body, RegisterPacketBody):
            src_pk = body.src_pk
            hops = body.return_hops
            self.register[src_pk] = hops
        elif isinstance(body, DataPacketBody):
            public_key = self.config.look_up_pk(self.ip)
            if public_key == body.dest_pk:
                self.on_data(body.src_pk, body.data, False)
            elif self.hidden_keypair[0] == body.dest_pk:
                self.on_data(body.src_pk, body.data, True)
            else:
                old_header = packet.header
                hops = self.register[body.dest_pk]
                next_ip = blob_rsa_dec(hops[0], public_key)
                next_node_pk = self.config.look_up_pk(next_ip)
                random_hob_ip = os.urandom(256)
                changed_hobs = packet.header.hops[1:].append(random_hob_ip)
                new_header = Header(old_header.length, changed_hobs)
                new_packet = Packet(new_header, body)
                self.netman.convey_packet(self.ip, next_ip, new_packet.to_bytes(public_key, next_node_pk))

    @property
    def address(self):
        return RelayAddress(ip=self.ip, pk=self.pubkey)

    def on_data(self, sender_pk, payload, hidden=False):
        """
        Called when a data packet is delivered to its final
        recipient
        """
        message = blob_rsa_dec(payload, self.privkey if not hidden else self.hidden_keypair[1])
        print("Message:", message, "from", sender_pk)

    def build_circuit(self, from_node, to_node):
        """
        Based on relay's configurations, this method should return a path

        from the first node to the other, with the following characteristics:
        i)   the minimum (edge count) length of the path should be 4
        ii)  the middle nodes should cross at least two different countries
             HINT: use get_ip_country() to look up country of and IP addr
        iii) the number of hops be the minimum possible
        iv)  the path should have the minimum weighted length amongst all
             paths having features i, ii and iii.
             The edge weights indicates network latency (the lower, the better)

        Use the Data Structure & Algorithms force, Luke :)

        :param from_node: start node (IP)
        :param to_node: target node (IP)
        :return: List<bytes (IP addresses)> - list of all nodes (denoted by IP) in the path including start and end
        """
        net_graph = self.config.net_grap
        relay_list = self.config.relay_list
        dist_map = self.config.dist_map
        graph = Graph(len(relay_list))
        for t in net_graph:
            graph.addEdge(relay_list.index(t[0]), relay_list.index(t[1]))

        all_paths = list()
        visited_nodes = [False for i in range(len(relay_list))]
        find_all_paths(graph, relay_list.index(from_node), relay_list.index(to_node), visited_nodes, list(), all_paths)

        path_len = [(all_paths[i], len(all_paths[i])) for i in range(len(all_paths)) if len(all_paths[i]) < 7]
        sorted_path_len = sorted(path_len, key=lambda x: x[1])
        sorted_path = [i[0] for i in sorted_path_len]
        two_country_path = list()
        for path in sorted_path:
            is_ok = False
            first_country = self.netman.get_ip_country(relay_list[path[1]])
            for index in path[2:-1]:
                index_country = self.netman.get_ip_country(relay_list[path[index]])
                if first_country != index_country:
                    is_ok = True
                    break
            if is_ok:
                two_country_path.append(path)
        if len(two_country_path) == 0:
            print('error there is no path with 2 different country !')
            return list()

        paths = [path for path in two_country_path if len(path) == len(two_country_path[0])]
        if len(paths) > 1:
            min_weight = math.inf
            min_path = []
            for path in paths:
                weight = 0
                for i in path[:-1]:
                    weight += dist_map[(relay_list[i], relay_list[i+1])]
                if weight < min_weight:
                    min_weight = weight
                    min_path = path
        elif len(paths) == 1:
            min_path = paths[0]
        else:
            return list()
        return [relay_list[i] for i in min_path]







    def register_on(self, target_node, go_route, return_route):
        """
        creates a packet for registering itself on target_node
        based on the provided forth and backward routes and sends it

        :param target_node: RelayAddress
        :param go_route: List<bytes (IP addresses)> path from current node to the target node INCLUDING themselves
        :param return_route: List<bytes (IP addresses)> path from target node to the current node INCLUDING themselves
        """
        # make register body
        enc_hobs = encrypt_hobs(return_route, self.config)
        my_hidden_pk = self.hidden_keypair[0]
        register_packet = RegisterPacketBody(my_hidden_pk, enc_hobs, self.challenge())

        # make header
        enc_hobs = encrypt_hobs(go_route, self.config)
        header = Header(None, enc_hobs)

        new_packet = Packet(header, register_packet)
        hh_pk = self.config.look_up_pk(target_node)
        next_hop_pk = self.config.look_up_pk(go_route[1])
        new_packet_bytes = new_packet.to_bytes(next_hop_pk, hh_pk)
        new_packet.header.length = len(new_packet_bytes)
        self.netman.convey_packet(self.ip, go_route[1], new_packet_bytes)

    def send_data_hidden(self, message_raw, hidden_handler, dest_pk, route):
        """
        Sends a packet to a hidden TorToar circuit. (dark-web-ish data node)

        :param message_raw: bytes
        :param hidden_handler: RelayAddress
        :param dest_pk: rsa.PublicKey - public key of hidden target node
        :param route: List<bytes (IP addresses)> - path from current node to the target node INCLUDING themselves
        """
        # make body
        my_pk = self.config.look_up_pk(self.ip)
        register_packet = DataPacketBody(dest_pk, my_pk, message_raw)

        # make header
        enc_hobs = encrypt_hobs(route, self.config)
        header = Header(None, enc_hobs)

        new_packet = Packet(header, register_packet)
        hh_pk = self.config.look_up_pk(hidden_handler.ip)
        next_hop_pk = self.config.look_up_pk(route[1])
        new_packet_bytes = new_packet.to_bytes(next_hop_pk, hh_pk)
        new_packet.header.length = len(new_packet_bytes)
        self.netman.convey_packet(self.ip, route[1], new_packet_bytes)

    def send_data_simple(self, message_raw, relay_address, route):
        """
        send a normal (not hidden) data packet through the given hops
        :param message_raw: bytes - the message to be sent
        :param relay_address: RelayAddress - target node address
        :param route: List<bytes (IP addresses)> - path from current node to the target node INCLUDING themselves
        """
        # make body
        my_pk = self.config.look_up_pk(self.ip)
        register_packet = DataPacketBody(relay_address.pk, my_pk, message_raw)

        # make header
        enc_hobs = encrypt_hobs(route, self.config)
        header = Header(None, enc_hobs)

        new_packet = Packet(header, register_packet)
        next_hop_pk = self.config.look_up_pk(route[1])
        new_packet_bytes = new_packet.to_bytes(next_hop_pk, relay_address.pk)
        new_packet.header.length = len(new_packet_bytes)
        self.netman.convey_packet(self.ip, route[1], new_packet_bytes)

    def challenge(self):
        """
        Used for generating the time based challenge required
        for registering on remote hosts
        :return: bytes - signed challenge (placed directly in register packet)
        """
        return rsa.sign(b"%d" % self.netman.current_time, self.privkey, "SHA-1")

    def verify(self, challenge, pubkey):
        """
        Used for verifying time based challenges when receiving
        register messages
        :param challenge: bytes - received challenge bytes
        :param pubkey: rsa.PublicKey - public key of the registering remote node
        :return: boolean - whether challenge is valid
        """
        try:
            return rsa.verify(self.netman.current_time, challenge, pubkey)
        except VerificationError:
            return False
