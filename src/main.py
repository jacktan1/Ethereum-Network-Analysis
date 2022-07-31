import pandas as pd
import rlp
import socket
import threading
import time
import warnings
from coincurve import PrivateKey, PublicKey
from Crypto.Hash import keccak
from .logger import initialize_logger


class NodeBase:
    def __init__(self, pub_key_hex: str, prv_key_hex: str):
        self.pub_key = bytes.fromhex(pub_key_hex)
        self.prv_key = bytes.fromhex(prv_key_hex)

    def calc_sig(self, packet_type: bytes, packet_payload: bytes):
        """
        Calculate message hash using secp256k1.

        :param packet_type: bytes
        :param packet_payload: bytes
        :return: bytes
        """
        msg_hash = self.calc_hash(packet_type + packet_payload)

        pk = PrivateKey(self.prv_key)

        return pk.sign_recoverable(msg_hash, hasher=None)

    def construct_packet(self, payload_list: list, packet_type: bytes):
        """
        Construct UDP packet according to standards listed in Node Discovery protocol ver. 4.

        :param payload_list: list of bytes, strings, ints to send
        :param packet_type: int
        :return: bytes
        """
        packet_payload = rlp.encode(payload_list)

        # Packet signature
        packet_sig = self.calc_sig(packet_type, packet_payload)

        # Packet hash
        packet_hash = self.calc_hash(packet_sig + packet_type + packet_payload)

        # Component order
        return packet_hash + packet_sig + packet_type + packet_payload

    def enr_extract(self, enr: list):
        """
        Extract info from Ethereum node record (enr).

        :param enr: list
        :return: str
        """
        node_ip = None
        node_udp = None
        node_tcp = None
        node_id_bytes = None
        node_id_str = None

        for n in range(len(enr)):
            if enr[n] == b'secp256k1':
                # Remove the first byte (node id type - compressed or uncompressed)
                node_id_bytes = PublicKey(enr[n + 1]).format(compressed=False)[1:]
                node_id_str = node_id_bytes.hex()
            elif enr[n] == b'ip':
                node_ip = self.bytes_to_ip(enr[n + 1])
            elif enr[n] == b'udp':
                node_udp = int.from_bytes(enr[n + 1], "big")
            elif enr[n] == b'tcp':
                node_tcp = int.from_bytes(enr[n + 1], "big")

        # Assert info is complete
        assert node_id_bytes and node_id_str and node_ip and node_udp

        if node_tcp & (node_tcp != node_udp):
            enode = f"enode://{node_id_str}@{node_ip}:{node_tcp}?discport={node_udp}"
        else:
            enode = f"enode://{node_id_str}@{node_ip}:{node_udp}"

        return {"ip": node_ip,
                "udp": node_udp,
                "tcp": node_tcp,
                "node id": node_id_bytes,
                "enode": enode}

    def nei_extract(self, nei: list):
        # [ip, udp-port, tcp-port, node-id]
        node_ip = self.bytes_to_ip(nei[0])
        node_udp = int.from_bytes(nei[1], "big")
        node_tcp = int.from_bytes(nei[2], "big")
        node_id_bytes = nei[3]
        node_id_str = node_id_bytes.hex()

        if node_tcp & (node_tcp != node_udp):
            enode = f"enode://{node_id_str}@{node_ip}:{node_tcp}?discport={node_udp}"
        else:
            enode = f"enode://{node_id_str}@{node_ip}:{node_udp}"

        return {"ip": node_ip,
                "udp": node_udp,
                "tcp": node_tcp,
                "node id": node_id_bytes,
                "enode": enode}

    def bucket_from_nodes(self, node_1: bytes, node_2: bytes):
        """
        Given two node IDs
            - Calculate node ID hashes
            - Find the index of the bit on which the hashes differ

        :param node_1: bytes (64-byte secp256k1 node public key)
        :param node_2: bytes (64-byte secp256k1 node public key)
        :return: int
        """
        k_bucket = None

        # Calc hash from node IDs and convert bytes to binary string
        binary_string_1 = bin(int.from_bytes(self.calc_hash(node_1), "big")).lstrip("0b")
        binary_string_2 = bin(int.from_bytes(self.calc_hash(node_2), "big")).lstrip("0b")

        assert len(binary_string_1) == len(binary_string_1)

        for n in range(len(binary_string_1)):
            if binary_string_1[n] == binary_string_2[n]:
                continue
            else:
                k_bucket = n
                break

        if k_bucket is None:
            warnings.warn("Not able to find differing bit between node hashes! Are they different?")

        return k_bucket

    @staticmethod
    def calc_hash(data: bytes):
        """
        Calculate Keccak-256 hash of input data

        :param data: bytes
        :return: bytes
        """
        k = keccak.new(digest_bits=256, data=data)

        return k.digest()

    @staticmethod
    def ip_to_bytes(ip: str):
        """
        Convert string ip "x.x.x.x" to bytes.

        :param ip: string
        :return: bytes
        """
        ip_list = ip.split(".")
        assert len(ip_list) == 4
        ip_bytes = b''.join([int(n).to_bytes(1, byteorder="big") for n in ip_list])

        return ip_bytes

    @staticmethod
    def bytes_to_ip(ip_bytes: bytes):
        """
        Convert IP bytes address to readable string ("x.x.x.x").

        :param ip_bytes: bytes
        :return: string
        """
        ip_hex = ip_bytes.hex()
        assert len(ip_hex) == 8
        ip_list = [str(int(ip_hex[i:i + 2], base=16)) for i in range(0, len(ip_hex), 2)]
        ip = ".".join(ip_list)

        return ip

    @staticmethod
    def get_packet_type(packet_type_int: int):
        assert packet_type_int in range(1, 7)
        if packet_type_int == 1:
            return "PING"
        elif packet_type_int == 2:
            return "PONG"
        elif packet_type_int == 3:
            return "FIND_NODE"
        elif packet_type_int == 4:
            return "NEIGHBORS"
        elif packet_type_int == 5:
            return "ENR_REQUEST"
        elif packet_type_int == 6:
            return "ENR_RESPONSE"


class NodeFun(NodeBase):
    def __init__(self, pub_key_hex: str, prv_key_hex: str,
                 ip_str: str, port_udp: int, port_tcp: int, version: int):
        super().__init__(pub_key_hex, prv_key_hex)
        self.ip_str = ip_str
        self.ip_bytes = self.ip_to_bytes(self.ip_str)
        self.udp = port_udp
        self.tcp = port_tcp
        self.version = version
        # Expiry threshold of udp packages
        self.wait_time = 30

    def ping(self, dst_ip_str: str, dst_port_udp: int, dst_port_tcp: int):
        """
        Ping Packet (0x01)

        :param dst_ip_str: destination node IP
        :param dst_port_udp: destination node UDP port
        :param dst_port_tcp: destination node TCP port
        :return: bytes
        """
        packet_type = int(1).to_bytes(1, byteorder="big")
        exp_time = int(time.time()) + self.wait_time

        # packet-data = [version, from, to, expiration, enr-seq ...]
        packet_payload_list = [self.version,
                               [self.ip_bytes, self.udp, self.tcp],
                               [self.ip_to_bytes(dst_ip_str), dst_port_udp, dst_port_tcp],
                               exp_time]

        return self.construct_packet(packet_payload_list, packet_type)

    def pong(self, dst_ip_str: str, dst_port_udp: int, ping_hash: bytes):
        """
        Pong Packet (0x02)

        :param dst_ip_str: destination node IP
        :param dst_port_udp: destination node UDP port
        :param ping_hash: hash of ping packet
        :return: bytes
        """
        packet_type = int(2).to_bytes(1, byteorder="big")
        exp_time = int(time.time()) + self.wait_time

        packet_payload_list = [[self.ip_to_bytes(dst_ip_str), dst_port_udp, 0],
                               ping_hash,
                               exp_time]

        return self.construct_packet(packet_payload_list, packet_type)

    def find_node(self, target_node: bytes):
        """
        FindNode Packet (0x03)

        :param target_node: bytes (64-byte secp256k1 node public key)
        :return: bytes
        """
        packet_type = int(3).to_bytes(1, byteorder="big")
        exp_time = int(time.time()) + self.wait_time

        packet_payload_list = [target_node, exp_time]

        return self.construct_packet(packet_payload_list, packet_type)

    def enr_request(self):
        """
        ENRRequest Packet (0x05)

        :return: bytes
        """
        packet_type = int(5).to_bytes(1, byteorder="big")
        exp_time = int(time.time()) + self.wait_time

        packet_payload_list = [exp_time]

        return self.construct_packet(packet_payload_list, packet_type)


class DiscSess:
    def __init__(self, node: NodeFun, port: int):
        self.node = node
        # All response packets received
        self.resp_df = pd.DataFrame(columns=["time", "ip", "udp", "raw",
                                             "hash", "sig", "type", "data"])
        # Routing table
        self.routing_df = pd.DataFrame(columns=["ip", "udp", "active",
                                                "first ping", "last ping",
                                                "node id", "enode"])
        self.logger = initialize_logger("logger", "logs", "udp.log")

        # UDP socket settings
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("", port))
        self.resp_timout = 10
        self.running = True

        # Start listening
        self.listening = threading.Thread(target=self.listen)
        self.listening.start()

    def listen(self):
        """
        Open socket port to listen for UDP traffic
        Automatically responds to Pings - time sensitive

        :return: None
        """
        while self.running:
            # Maximum packet size should not exceed 1280 bytes (discv4 spec.)
            resp, addr = self.socket.recvfrom(1280)

            # Filter out random / invalid packets
            if len(resp) > 97:
                # Respond to Pings
                if resp[97] == 1:
                    self.logger.info(f"Received PING from {addr[0]}:{addr[1]}")
                    pong_packet = self.node.pong(addr[0], addr[1], resp[:32])
                    self.socket.sendto(pong_packet, (addr[0], addr[1]))
                    self.logger.info(f"Sent PONG to {addr[0]}:{addr[1]}")

                # Schema: hash (32) | signature (64) | packet-type (1) | packet-data (>0)
                resp_dict = {"time": [time.time()],
                             "ip": [addr[0]],
                             "udp": [addr[1]],
                             "raw": [resp],
                             "hash": [resp[:32]],
                             "sig": [resp[32:97]],
                             "type": [resp[97]],
                             "data": [rlp.decode(resp[98:])]}

                # Add to response df
                self.resp_df = pd.concat([self.resp_df, pd.DataFrame.from_dict(resp_dict)],
                                         ignore_index=True)

        # Socket shutdown
        self.socket.shutdown(socket.SHUT_RDWR)
        self.socket.close()

    def terminate(self):
        """
        Terminate listening process

        :return: None
        """
        self.running = False

    def ping_connect(self, dst_ip: str, dst_udp: int, dst_tcp: int = 0):
        """
        1. Send Ping to dst_ip:dst_udp
        2. Check if received valid Pong
        3. Update routing table with ip, port, ping times

        :param dst_ip: destination node IP
        :param dst_udp: destination node UDP port
        :param dst_tcp: destination node TCP port
        :return: True if received valid Pong, otherwise False
        """
        ping_packet = self.node.ping(dst_ip, dst_udp, dst_tcp)
        self.socket.sendto(ping_packet, (dst_ip, dst_udp))
        self.logger.info(f"Sent PING to {dst_ip}:{dst_udp}")

        # Check for PONG response
        pong_resp = self.check_resp_packet(dst_ip, dst_udp, 2, 1)

        in_routing = self.in_routing_table({"ip": dst_ip,
                                            "udp": dst_udp})

        # If pong response received
        if pong_resp is not None:
            try:
                assert pong_resp.loc[0, "data"][1] == ping_packet[:32]
            except AssertionError as err:
                self.logger.error(f"{dst_ip}:{dst_udp} responded with mismatched Ping hash!")
                raise err

            # Update IP:port in routing table
            if in_routing:
                self.logger.info(f"Updated {dst_ip}:{dst_udp} in routing table")
                self.routing_df.loc[(self.routing_df["ip"] == dst_ip) &
                                    (self.routing_df["udp"] == dst_udp),
                                    ["active", "last ping"]] = [True, time.time()]
            # Add IP:port to routing table
            else:
                self.logger.info(f"Added {dst_ip}:{dst_udp} to routing table")
                self.routing_df = pd.concat([self.routing_df, pd.DataFrame.from_dict(
                    {"ip": [dst_ip],
                     "udp": [dst_udp],
                     "active": [True],
                     "first ping": [time.time()],
                     "last ping": [time.time()]})],
                                            ignore_index=True)

            return True
        else:
            # Remove IP:port active status
            if in_routing:
                self.logger.info(f"Marked {dst_ip}:{dst_udp} as inactive in routing table")
                self.routing_df.loc[(self.routing_df["ip"] == dst_ip)
                                    & (self.routing_df["udp"] == dst_udp), "active"] = False

            return False

    def nodeid_from_ip(self, dst_ip: str, dst_udp: int):
        """
        Get node information via ENR Request from IP:port
        Should only be used after Ping-Pong

        1. Send ENR Request to dst_ip:dst_udp
        2. Check if received valid ENR Response
        3. Update routing table with node id and enode address

        :param dst_ip: destination node IP
        :param dst_udp: destination node UDP port
        :return: True if received valid ENR Response, otherwise False
        """
        # Check IP:port already in routing table
        assert self.in_routing_table({"ip": dst_ip, "udp": dst_udp})

        enr_request_packet = self.node.enr_request()
        self.socket.sendto(enr_request_packet, (dst_ip, dst_udp))
        self.logger.info(f"Sent ENR_REQUEST to {dst_ip}:{dst_udp}")

        # Check for ENR response
        enr_resp = self.check_resp_packet(dst_ip, dst_udp, 6, 1)

        if enr_resp is not None:
            # Extract info from ENR
            node_dict = self.node.enr_extract(enr_resp.loc[0, "data"][1])

            # Sanity check
            assert node_dict["ip"] == dst_ip
            assert node_dict["udp"] == dst_udp

            # Add node ID
            self.routing_df.loc[(self.routing_df["ip"] == dst_ip)
                                & (self.routing_df["udp"] == dst_udp),
                                "node id"] = node_dict["node id"]

            # Add enode address
            self.routing_df.loc[(self.routing_df["ip"] == dst_ip)
                                & (self.routing_df["udp"] == dst_udp),
                                "enode"] = node_dict["enode"]

            self.logger.info(f"Added Node ID and enode for {dst_ip}:{dst_udp}")

            return True

        else:
            self.routing_df.loc[(self.routing_df["ip"] == dst_ip)
                                & (self.routing_df["udp"] == dst_udp), "active"] = False

            return False

    def get_neighbors(self, dst_ip: str, dst_udp: int, target_node: bytes):
        """
        Send a FindNode request to dst_ip:dst_udp regarding target_node
        For each node in the Neighbors response packet, send ping and ENR Request
        in the appropriate order, before adding them to the routing table

        1. Send FindNode request to dst_ip:dst_udp
        2. Check if received valid Neighbors responses (should be 2)
        3. Send Ping then ENR Request to all nodes in Neighbors responses
        4. Update routing table with Neighbor nodes


        :param dst_ip: destination node IP
        :param dst_udp: destination node UDP port
        :param target_node: target public node id (64 bytes) to find neighbors around
        :return: None
        """
        # Check IP:port already in routing table
        assert self.in_routing_table({"ip": dst_ip, "udp": dst_udp})

        find_node_packet = self.node.find_node(target_node)
        self.socket.sendto(find_node_packet, (dst_ip, dst_udp))
        self.logger.info(f"Sent FIND_NODE to {dst_ip}:{dst_udp}")

        # Check for Neighbors response
        nei_resp = self.check_resp_packet(dst_ip, dst_udp, 4, 2)

        if nei_resp is not None:
            # Sanity check
            assert nei_resp.shape[0] == 2

            nei_list = nei_resp.loc[0, "data"][0] + nei_resp.loc[1, "data"][0]

            for nei in nei_list:
                # Extract info from Neighbors response
                node_dict = self.node.nei_extract(nei)

                if self.ping_connect(node_dict["ip"], node_dict["udp"], node_dict["tcp"]):
                    if self.nodeid_from_ip(node_dict["ip"], node_dict["udp"]):
                        # Sanity check
                        if not all(self.routing_df.loc[(self.routing_df["ip"] == node_dict["ip"])
                                                       & (self.routing_df["udp"] == node_dict["udp"]),
                                                       ["node id", "enode"]] == [node_dict["node id"],
                                                                                 node_dict["enode"]]):
                            self.logger.warn(f'Node ID / Enode {node_dict["ip"]}:{node_dict["udp"]} do not'
                                             f'match between Neighbor Response and ENR Response')

    def in_routing_table(self, input_dict: dict):
        """
        Check if keys-value pairs in input_dict are in routing table

        :param input_dict: dictionary
        :return: True / False
        """
        # Check that all keys in dictionary are valid column names in routing table
        assert all([n in self.routing_df.columns for n in input_dict.keys()])

        # Filter via key:value pairs
        routing_df1 = self.routing_df[[all([self.routing_df.loc[m, n] == input_dict[n] for n in input_dict])
                                       for m in self.routing_df.index]]

        # Assert that only one entry in routing table satisfies condition
        if routing_df1.shape[0] > 1:
            self.logger.error(f"{routing_df1.shape[0]} routing table entries returned via conditions: {input_dict}")
            raise Exception
        elif routing_df1.shape[0] == 1:
            return True
        else:
            return False

    def check_resp_packet(self, src_ip: str, src_udp: int, packet_type: int, num_packets: int):
        """
        Checks for response packet(s) by ip, udp, packet type and packet arrival time
        Returns most recent packet(s), otherwise return None

        :param src_ip: source node IP
        :param src_udp: source node UDP port
        :param packet_type: type of packet ([1, 6])
        :param num_packets: number of packets to retrieve (e.g. 2 for neighbors etc.)
        :return: response packet(s) (pandas.Series)
        """
        num_retries = 0
        max_retries = 5
        wait_time = 1
        success_resp = False
        resp_df1 = None
        packet_type_str = self.node.get_packet_type(packet_type)

        # See if any valid responses in last `self.resp_timout` seconds
        while (num_retries < max_retries) & (not success_resp):
            resp_df1 = self.resp_df[(self.resp_df["ip"] == src_ip)
                                    & (self.resp_df["udp"] == src_udp)
                                    & (self.resp_df["time"] >= time.time() - self.resp_timout)
                                    & (self.resp_df["type"] == packet_type)].sort_values(by="time", ascending=False)

            if resp_df1.shape[0] >= num_packets:
                # Take most recent num_packets if there are excess
                resp_df1 = resp_df1.iloc[-num_packets:].reset_index(drop=True)
                success_resp = True
            else:
                time.sleep(wait_time)
                num_retries += 1

        if success_resp:
            self.logger.info(f"Retrieved {num_packets} {packet_type_str} packet(s) from "
                             f"{src_ip}:{src_udp}")
            return resp_df1
        else:
            self.logger.warn(f"Unable to retrieve {num_packets} {packet_type_str} packet(s) from "
                             f"{src_ip}:{src_udp}. Waited ~{num_retries * wait_time} seconds")
            return None
