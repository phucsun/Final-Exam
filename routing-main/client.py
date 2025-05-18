import time
import queue
from packet import Packet


class Client:
    """
    The Client class sends periodic "traceroute" packets and returns routes that
    these packets take back to the network object.
    """

    def __init__(self, addr, all_clients, send_rate, update_fn):
        self.addr = addr
        self.all_clients = all_clients
        self.send_rate = send_rate
        self.last_time = 0
        self.link = None
        self.update_fn = update_fn
        self.sending = True
        self.link_changes = queue.Queue()
        self.keep_running = True

    def change_link(self, change):
        """Add a link to the client.

        The change argument should be a tuple ('add', link).
        """
        self.link_changes.put(change)

    def handle_packet(self, packet):
        """Handle receiving a packet.

        If it is a routing packet, ignore. If it is a "traceroute" packet, update the
        network object with its route.
        """
        if packet.kind == Packet.TRACEROUTE:
            self.update_fn(packet.src_addr, packet.dst_addr, packet.route)

    def send_traceroutes(self):
        """Send "traceroute" packets to every other client in the network."""
        for dst_client in self.all_clients:
            packet = Packet(Packet.TRACEROUTE, self.addr, dst_client)
            if self.link:
                self.link.send(packet, self.addr)
            self.update_fn(packet.src_addr, packet.dst_addr, [])

    def handle_time(self, time_ms):
        """Send traceroute packets regularly."""
        if self.sending and (time_ms - self.last_time > self.send_rate):
            self.send_traceroutes()
            self.last_time = time_ms

    def run(self):
        """Main loop of client."""
        while self.keep_running:
            time.sleep(0.1)
            time_ms = int(round(time.time() * 1000))
            try:
                change = self.link_changes.get_nowait()
                if change[0] == "add":
                    self.link = change[1]
            except queue.Empty:
                pass
            if self.link:
                packet = self.link.recv(self.addr)
                if packet:
                    self.handle_packet(packet)
            self.handle_time(time_ms)

    def last_send(self):
        """Send one final batch of "traceroute" packets."""
        self.sending = False
        self.send_traceroutes()
