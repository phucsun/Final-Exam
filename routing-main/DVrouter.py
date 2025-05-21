from router import Router
from packet import Packet
from collections import defaultdict
import copy
import json
import logging

# Thiết lập logging để gỡ lỗi
# logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class DVrouter(Router):
    """Distance vector routing protocol implementation."""

    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)  # Initialize base class
        self.heartbeat_time = heartbeat_time
        self.last_time = 0
        # Distance vector: {dst: (cost, next_hop)}
        self.distance_vector = defaultdict(lambda: (16, None))
        self.distance_vector[self.addr] = (0, self.addr)  # Cost to self is 0
        # Forwarding table: {dst: port}
        self.forwarding_table = {}
        # Neighbor distance vectors: {neighbor: {dst: cost}}
        self.neighbor_vectors = defaultdict(dict)
        # Neighbor ports: {neighbor: port}
        self.neighbors = {}
        # Neighbor costs: {neighbor: cost}
        self.neighbor_costs = {}

    def handle_packet(self, port, packet):
        """Process incoming packet."""
        if packet.is_traceroute:
            # Chuyển tiếp gói tin traceroute nếu đích có trong forwarding table
            if packet.dst_addr in self.forwarding_table:
                self.send(self.forwarding_table[packet.dst_addr], packet)
        else:
            # Xử lý gói tin routing
            neighbor = packet.src_addr
            try:
                received_vector = json.loads(packet.content)
            except json.JSONDecodeError:
                # logging.error(f"Router {self.addr}: Failed to parse routing packet from {neighbor}")
                return
            # Kiểm tra dữ liệu đầu vào
            if not isinstance(received_vector, dict):
                # logging.error(f"Router {self.addr}: Invalid distance vector format from {neighbor}")
                return
            update = False
            self.neighbor_vectors[neighbor] = copy.deepcopy(received_vector)

            for dst, cost in received_vector.items():
                if dst == self.addr or float(cost) < 0:
                    continue
                new_cost = self.neighbor_costs.get(neighbor, 16) + float(cost)
                if new_cost > 16:  # Giới hạn chi phí tối đa
                    new_cost = 16
                current_cost, current_next_hop = self.distance_vector.get(dst, (16, None))
                if new_cost < current_cost:
                    self.distance_vector[dst] = (new_cost, neighbor)
                    self.forwarding_table[dst] = self.neighbors[neighbor]
                    update = True
                    # logging.debug(f"Router {self.addr}: Updated route to {dst} via {neighbor} with cost {new_cost}")
                elif current_next_hop == neighbor and new_cost != current_cost:
                    # Chi phí thay đổi qua next hop hiện tại, cần tái tính toán
                    self._recalculate_distance_vector()
                    update = True
                    # logging.debug(f"Router {self.addr}: Recalculated routes due to cost change to {dst} via {neighbor}")
            for dst in list(self.distance_vector.keys()):
                if dst == self.addr:
                    continue
                current_cost, current_next_hop = self.distance_vector[dst]
                if current_next_hop == neighbor and dst not in received_vector:
                    del self.distance_vector[dst]
                    self.forwarding_table.pop(dst, None)
                    self._recalculate_distance_vector()
                    update = True
            if update:
                self._broadcast_distance_vector()

    def handle_new_link(self, port, endpoint, cost):
        """Handle new link."""
        if endpoint == self.addr or cost < 0:
            return
        # Thêm láng giềng
        self.neighbors[endpoint] = port
        self.neighbor_costs[endpoint] = cost
        # Cập nhật distance vector và forwarding table cho láng giềng mới
        self.distance_vector[endpoint] = (cost, endpoint)
        self.forwarding_table[endpoint] = port
        # logging.debug(f"Router {self.addr}: Added link to {endpoint} on port {port} with cost {cost}")
        # Tái tính toán distance vector
        self._recalculate_distance_vector()
        # Gửi distance vector mới
        self._broadcast_distance_vector()

    def handle_remove_link(self, port):
        """Handle removed link."""
        # Tìm láng giềng liên quan đến cổng
        neighbor = None
        for addr, p in self.neighbors.items():
            if p == port:
                neighbor = addr
                break
        if neighbor:
            # Xóa láng giềng và dữ liệu liên quan
            self.neighbors.pop(neighbor, None)
            self.neighbor_costs.pop(neighbor, None)
            self.neighbor_vectors.pop(neighbor, None)
            # Xóa các đích có next_hop là láng giềng bị xóa
            for dst in list(self.distance_vector.keys()):
                if self.distance_vector[dst][1] == neighbor:
                    self.distance_vector.pop(dst, None)
                    # Nếu đích không còn trong bảng định tuyến, xóa khỏi forwarding table
                    if dst in self.forwarding_table:
                        self.forwarding_table.pop(dst, None)
            # logging.debug(f"Router {self.addr}: Removed link to {neighbor}, set affected destinations to infinity")
            # Tái tính toán distance vector
            self._recalculate_distance_vector()
            # Gửi distance vector mới
            self._broadcast_distance_vector()

    def handle_time(self, time_ms):
        """Handle current time."""
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            # Gửi distance vector định kỳ
            self._broadcast_distance_vector()

    def _recalculate_distance_vector(self):
        """Recalculate distance vector using Bellman-Ford."""
        # Tạo distance vector và forwarding table mới
        new_dv = defaultdict(lambda: (16, None))
        new_dv[self.addr] = (0, self.addr)
        new_ft = {}

        # Lấy tất cả đích từ neighbor_vectors
        all_dests = set()
        for vector in self.neighbor_vectors.values():
            all_dests.update(vector.keys())
    
        # Tính toán đường đi chi phí thấp nhất cho mỗi đích
        for dst in all_dests:
            if dst == self.addr:
                continue
            min_cost = 16
            min_neighbor = None
            min_port = None
            for neighbor, vector in self.neighbor_vectors.items():
                if dst in vector:
                    cost = self.neighbor_costs[neighbor] + float(vector[dst])
                    if cost > 16:  # Giới hạn chi phí tối đa
                        cost = 16
                    if cost < min_cost:
                        min_cost = cost
                        min_neighbor = neighbor
                        min_port = self.neighbors[neighbor]
            if min_cost < 16:
                new_dv[dst] = (min_cost, min_neighbor)
                new_ft[dst] = min_port

        # Cập nhật cho các láng giềng trực tiếp
        for neighbor, port in self.neighbors.items():
            direct_cost = self.neighbor_costs[neighbor]
            if direct_cost < new_dv[neighbor][0]:  # Chỉ cập nhật nếu tốt hơn
                new_dv[neighbor] = (direct_cost, neighbor)
                new_ft[neighbor] = port

        # Cập nhật distance vector và forwarding table
        self.distance_vector = new_dv
        self.forwarding_table = new_ft
        # logging.debug(f"Router {self.addr}: Updated distance vector: {dict(self.distance_vector)}")

    def _broadcast_distance_vector(self):
        """Broadcast distance vector to all neighbors with poisoned reverse."""
        for neighbor, port in self.neighbors.items():
            # Tạo distance vector với poisoned reverse
            dv = {}
            for dst, (cost, next_hop) in self.distance_vector.items():
                if next_hop == neighbor and cost < 16:
                    # Poisoned reverse: gửi chi phí vô cực cho đích có next_hop là neighbor
                    dv[dst] = 16
                else:
                    dv[dst] = cost
            packet = Packet(Packet.ROUTING, self.addr, None, content=json.dumps(dv))
            self.send(port, packet)
            logging.debug(f"Router {self.addr}: Broadcast distance vector to {neighbor} on port {port}: {dv}")

    def __repr__(self):
        """Representation for debugging in the network visualizer."""
        dv_str = ", ".join(f"{dst}: {cost}" for dst, (cost, _) in self.distance_vector.items())
        return f"DVrouter(addr={self.addr}, DV={{{dv_str}}})"
