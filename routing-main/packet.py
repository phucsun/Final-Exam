import copy


class Packet:
    """
    The Packet class defines packets that clients and routers send in the simulated
    network.

    Parameters
    ----------
    kind
        Either Packet.TRACEROUTE or Packet.ROUTING. Use Packet.ROUTING for all packets
        created by your implementations.
    src_addr
        The address of the source of the packet.
    dst_addr
        The address of the destination of the packet.
    content
        The content of the packet. Must be a string.
    """
    #Traceruoute (Check đúng sai)  là dùng để kiểm tra đường đi của gói tin, sau khi mà mình đã xác định được đường đi của gói tin thì mình sẽ dùng Traceroute để kiểm tra xem đường đi đó có đúng hay không
    #Routing (Tìm đường) là dùng để định tuyến gói tin từ nguồn đến đích, nó sẽ tìm đường đi tốt nhất cho gói tin từ nguồn đến đích
    TRACEROUTE = 1
    ROUTING = 2

    def __init__(self, kind, src_addr, dst_addr, content=None):
        self.kind = kind
        self.src_addr = src_addr
        self.dst_addr = dst_addr
        self.content = content
        self.route = [src_addr]

    def copy(self):
        """Create a deep copy of the packet.
        This gets called automatically when the packet is sent to avoid aliasing issues.
        """
        content = copy.deepcopy(self.content)
        p = Packet(self.kind, self.src_addr, self.dst_addr, content=content)
        p.route = list(self.route)
        return p

    @property
    def is_traceroute(self):
        """Returns True if the packet is a traceroute packet."""
        return self.kind == Packet.TRACEROUTE

    @property
    def is_routing(self):
        """Returns True is the packet is a routing packet."""
        return self.kind == Packet.ROUTING

    def add_to_route(self, addr):
        """DO NOT CALL from DVrouter or LSrouter!"""
        self.route.append(addr)

    def animate_send(self, src, dst, latency):
        """DO NOT CALL from DVrouter or LSrouter!"""
        if hasattr(Packet, "animate"):
            Packet.animate(self, src, dst, latency)
