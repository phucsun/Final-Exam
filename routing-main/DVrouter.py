####################################################
# DVrouter.py
# Name: [Your Name]
# HUID: [Your HUID]
#####################################################

from router import Router
from packet import Packet
from collections import defaultdict
import copy
import json

class DVrouter(Router):
    """Distance vector routing protocol implementation."""

    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)  # Initialize base class
        self.heartbeat_time = heartbeat_time
        self.last_time = 0
        # Distance vector: {dst: (cost, next_hop)}
        self.distance_vector = defaultdict(lambda: (float('inf'), None))
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
            # Forward traceroute packet if destination is in forwarding table
            if packet.dst_addr in self.forwarding_table:
                self.send(self.forwarding_table[packet.dst_addr], packet)
        else:
            # Handle routing packet (distance vector update)
            neighbor = packet.src_addr
            # Convert string content back to dictionary
            try:
                received_vector = json.loads(packet.content)
            except json.JSONDecodeError:
                return  # Ignore invalid packets

            updated = False
            # Store neighbor's distance vector
            self.neighbor_vectors[neighbor] = copy.deepcopy(received_vector)

            # Update distance vector using Bellman-Ford
            for dst, cost in received_vector.items():
                if dst == self.addr:
                    continue  # Skip self
                # Cost to dst via neighbor = cost to neighbor + neighbor's cost to dst
                new_cost = self.neighbor_costs.get(neighbor, float('inf')) + float(cost)
                current_cost, _ = self.distance_vector[dst]
                if new_cost < current_cost:
                    # Update distance vector and forwarding table
                    self.distance_vector[dst] = (new_cost, neighbor)
                    self.forwarding_table[dst] = self.neighbors[neighbor]
                    updated = True
                elif self.distance_vector[dst][1] == neighbor and new_cost > current_cost:
                    # Recalculate path if cost via current next_hop increases
                    self._recalculate_distance_vector()
                    updated = True

            # Broadcast updated distance vector if changed
            if updated:
                self._broadcast_distance_vector()

    def handle_new_link(self, port, endpoint, cost):
        """Handle new link."""
        # Add neighbor
        self.neighbors[endpoint] = port
        self.neighbor_costs[endpoint] = cost
        # Update distance vector for new neighbor
        self.distance_vector[endpoint] = (cost, endpoint)
        self.forwarding_table[endpoint] = port
        # Recalculate distance vector for all destinations
        self._recalculate_distance_vector()
        # Broadcast updated distance vector
        self._broadcast_distance_vector()

    def handle_remove_link(self, port):
        """Handle removed link."""
        # Find neighbor associated with port
        neighbor = None
        for addr, p in self.neighbors.items():
            if p == port:
                neighbor = addr
                break
        if neighbor:
            # Remove neighbor and associated data
            del self.neighbors[neighbor]
            del self.neighbor_costs[neighbor]
            del self.neighbor_vectors[neighbor]
            # Remove from distance vector if next_hop is neighbor
            for dst in list(self.distance_vector.keys()):
                if self.distance_vector[dst][1] == neighbor:
                    del self.distance_vector[dst]
                    if dst in self.forwarding_table:
                        del self.forwarding_table[dst]
            # Recalculate distance vector
            self._recalculate_distance_vector()
            # Broadcast updated distance vector
            self._broadcast_distance_vector()

    def handle_time(self, time_ms):
        """Handle current time."""
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            # Broadcast distance vector periodically
            self._broadcast_distance_vector()

    def _recalculate_distance_vector(self):
        """Recalculate distance vector using Bellman-Ford."""
        # Reset distance vector except for self
        new_dv = defaultdict(lambda: (float('inf'), None))
        new_dv[self.addr] = (0, self.addr)
        new_ft = {}

        # For each destination in neighbor vectors
        all_dests = set()
        for vector in self.neighbor_vectors.values():
            all_dests.update(vector.keys())

        for dst in all_dests:
            if dst == self.addr:
                continue
            # Find minimum cost path
            min_cost = float('inf')
            min_neighbor = None
            min_port = None
            for neighbor, vector in self.neighbor_vectors.items():
                if dst in vector:
                    cost = self.neighbor_costs[neighbor] + float(vector[dst])
                    if cost < min_cost:
                        min_cost = cost
                        min_neighbor = neighbor
                        min_port = self.neighbors[neighbor]
            if min_cost < float('inf'):
                new_dv[dst] = (min_cost, min_neighbor)
                new_ft[dst] = min_port

        # Update for direct neighbors
        for neighbor, port in self.neighbors.items():
            cost = self.neighbor_costs[neighbor]
            new_dv[neighbor] = (cost, neighbor)
            new_ft[neighbor] = port

        # Update distance vector and forwarding table
        self.distance_vector = new_dv
        self.forwarding_table = new_ft

    def _broadcast_distance_vector(self):
        """Broadcast distance vector to all neighbors."""
        # Create routing packet with distance vector as JSON string
        dv = {dst: cost for dst, (cost, _) in self.distance_vector.items()}
        packet = Packet(Packet.ROUTING, self.addr, None, content=json.dumps(dv))
        # Send to all neighbors
        for port in self.neighbors.values():
            self.send(port, packet)

    def __repr__(self):
        """Representation for debugging in the network visualizer."""
        dv_str = ", ".join(f"{dst}: {cost}" for dst, (cost, _) in self.distance_vector.items())
        return f"DVrouter(addr={self.addr}, DV={{{dv_str}}})"

