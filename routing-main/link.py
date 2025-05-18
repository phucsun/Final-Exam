import _thread
import sys
import queue
import time


class Link:
    """
    The Link class represents link between two routers/clients handles sending and
    receiving packets using threadsafe queues.

    Parameters
    ----------
    e1, e2
        The addresses of the two endpoints of the link.
    l12, l21
        The latencies (in ms) in the e1->e2 and e2->e1 directions, respectively.
    """

    def __init__(self, e1, e2, l12, l21, latency):
        self.q12 = queue.Queue()
        self.q21 = queue.Queue()
        self.l12 = l12 * latency
        self.l21 = l21 * latency
        self.latency_multiplier = latency
        self.e1 = e1
        self.e2 = e2

    def _send_helper(self, packet, src):
        """
        Run in a separate thread and send packet on link from `src` after waiting for
        the appropriate latency.
        """
        if src == self.e1:
            packet.add_to_route(self.e2)
            packet.animate_send(self.e1, self.e2, self.l12)
            time.sleep(self.l12 / 1000)
            self.q12.put(packet)
        elif src == self.e2:
            packet.add_to_route(self.e1)
            packet.animate_send(self.e2, self.e1, self.l21)
            time.sleep(self.l21 / 1000)
            self.q21.put(packet)
        sys.stdout.flush()

    def send(self, packet, src):
        """
        Send packet on link from `src`. Checks that packet content is a string and
        starts a new thread to send it. `src` must be equal to `self.e1` or `self.e2`.
        """
        if packet.content:
            assert isinstance(packet.content, str), "Packet content must be a string"
        p = packet.copy()
        _thread.start_new_thread(self._send_helper, (p, src))

    def recv(self, dst, timeout=None):
        """
        Check whether a packet is ready to be received by `dst` on this link. `dst` must
        be equal to `self.e1` or `self.e2`. If the packet is ready, return the packet,
        otherwise return `None`.
        """
        if dst == self.e1:
            try:
                packet = self.q21.get_nowait()
                return packet
            except queue.Empty:
                return None
        elif dst == self.e2:
            try:
                packet = self.q12.get_nowait()
                return packet
            except queue.Empty:
                return None

    def change_latency(self, src, c):
        """
        Update the latency of sending on the link from `src`.
        """
        if src == self.e1:
            self.l12 = c * self.latency_multiplier
        elif src == self.e2:
            self.l21 = c * self.latency_multiplier