import argparse
import sys
import threading
import json
import pickle
import signal
import time
import queue
from collections import defaultdict
from client import Client
from link import Link
from router import Router


def json_load_byteified(file_handle):
    return _byteify(json.load(file_handle, object_hook=_byteify), ignore_dicts=True)


def _byteify(data, ignore_dicts=False):
    # If this is a unicode string, return its string representation
    if isinstance(data, str):
        return data.encode("utf-8")
    # If this is a list of values, return list of byteified values
    if isinstance(data, list):
        return [_byteify(item, ignore_dicts=True) for item in data]
    # If this is a dictionary, return dictionary of byteified keys and values
    # but only if we haven't already byteified it
    if isinstance(data, dict) and not ignore_dicts:
        return {
            _byteify(key, ignore_dicts=True): _byteify(value, ignore_dicts=True)
            for key, value in data.items()
        }
    # If this is anything else, return it in its original form
    return data


class Network:
    """The Network class maintains all clients, routers, links, and confguration.

    Parameters
    ----------
    net_json_path
        The path to the JSON file that contains the network configurations.
    RouterClass
        Whether to use DVrouter, LSrouter, or the default router.
    visualize
        Whether to visualize the network.
    """

    def __init__(self, net_json_path, RouterClass, visualize=False):
        # Parse configuration details
        with open(net_json_path, "r") as f:
            net_json = json.load(f)
        self.latency_multiplier = 100
        self.end_time = net_json["end_time"] * self.latency_multiplier
        self.visualize = visualize
        if visualize:
            self.latency_multiplier *= net_json["visualize"]["time_multiplier"]
        self.client_send_rate = net_json["client_send_rate"] * self.latency_multiplier

        # Parse and create routers, clients, and links
        self.routers = self.parse_routers(net_json["routers"], RouterClass)
        self.clients = self.parse_clients(net_json["clients"], self.client_send_rate)
        self.links = self.parse_links(net_json["links"])

        # Parse link changes
        if "changes" in net_json:
            self.changes = self.parse_changes(net_json["changes"])
        else:
            self.changes = None

        # Parse correct routes and create some tracking fields
        self.correct_routes = self.parse_correct_routes(net_json["correct_routes"])
        self.threads = []
        self.routes = {}
        self.routes_lock = threading.Lock()

    def parse_routers(self, router_params, RouterClass):
        """Parse routes from the `router_params` dict."""
        routers = {}
        for addr in router_params:
            routers[addr] = RouterClass(
                addr, heartbeat_time=self.latency_multiplier * 10
            )
        return routers

    def parse_clients(self, client_params, client_send_rate):
        """Parse clients from `client_params` dict."""
        clients = {}
        for addr in client_params:
            clients[addr] = Client(
                addr, client_params, client_send_rate, self.update_route
            )
        return clients

    def parse_links(self, link_params):
        """Parse links from the `link_params` dict."""
        links = {}
        for addr1, addr2, p1, p2, c12, c21 in link_params:
            link = Link(addr1, addr2, c12, c21, self.latency_multiplier)
            links[(addr1, addr2)] = (p1, p2, c12, c21, link)
        return links

    def parse_changes(self, changes_params):
        """Parse link changes from the `changes_params` dict."""
        changes = queue.PriorityQueue()
        for change in changes_params:
            changes.put(change)
        return changes

    def parse_correct_routes(self, routes_params):
        """Parse correct routes from the `routes_params` dict/"""
        correct_routes = defaultdict(list)
        for route in routes_params:
            src, dst = route[0], route[-1]
            correct_routes[(src, dst)].append(route)
        return correct_routes

    def run(self):
        """Run the network.

        Start threads for each client and router. Start thread to track link changes.
        If not visualizing, wait until end time and print the final routes.
        """
        for router in self.routers.values():
            thread = RouterThread(router)
            thread.start()
            self.threads.append(thread)
        for client in self.clients.values():
            thread = ClientThread(client)
            thread.start()
            self.threads.append(thread)
        self.add_links()
        if self.changes:
            self.handle_changes_thread = HandleChangesThread(self)
            self.handle_changes_thread.start()

        if not self.visualize:
            signal.signal(signal.SIGINT, self.handle_interrupt)
            time.sleep(self.end_time / 1000)
            self.final_routes()
            sys.stdout.write("\n" + self.get_route_string() + "\n")
            self.join_all()

    def add_links(self):
        """Add links to clients and routers."""
        for addr1, addr2 in self.links:
            p1, p2, c12, c21, link = self.links[(addr1, addr2)]
            if addr1 in self.clients:
                self.clients[addr1].change_link(("add", link))
            if addr2 in self.clients:
                self.clients[addr2].change_link(("add", link))
            if addr1 in self.routers:
                self.routers[addr1].change_link(("add", p1, addr2, link, c12))
            if addr2 in self.routers:
                self.routers[addr2].change_link(("add", p2, addr1, link, c21))

    def handle_changes(self):
        """Handle changes to links.

        Run this method in a separate thread. Use a priority queue to track the time of
        next change.
        """
        start_time = time.time() * 1000
        while not self.changes.empty():
            change_time, target, change = self.changes.get()
            current_time = time.time() * 1000
            wait_time = (
                change_time * self.latency_multiplier + start_time
            ) - current_time
            if wait_time > 0:
                time.sleep(wait_time / 1000)

            # Link changes
            if change == "up":
                addr1, addr2, p1, p2, c12, c21 = target
                link = Link(addr1, addr2, c12, c21, self.latency_multiplier)
                self.links[(addr1, addr2)] = (p1, p2, c12, c21, link)
                self.routers[addr1].change_link(("add", p1, addr2, link, c12))
                self.routers[addr2].change_link(("add", p2, addr1, link, c21))
            elif change == "down":
                addr1, addr2 = target
                p1, p2, _, _, link = self.links[(addr1, addr2)]
                self.routers[addr1].change_link(("remove", p1))
                self.routers[addr2].change_link(("remove", p2))

            # Update visualization
            if hasattr(Network, "visualize_changes_callback"):
                Network.visualize_changes_callback(change, target)

    def update_route(self, src, dst, route):
        """
        Callback function used by clients to update the current routes taken by
        traceroute packets.
        """
        self.routes_lock.acquire()
        time_ms = int(round(time.time() * 1000))
        is_good = route in self.correct_routes[(src, dst)]
        try:
            _, _, current_time = self.routes[(src, dst)]
            if time_ms > current_time:
                self.routes[(src, dst)] = (route, is_good, time_ms)
        except KeyError:
            self.routes[(src, dst)] = (route, is_good, time_ms)
        finally:
            self.routes_lock.release()

    def get_route_string(self, label_incorrect=True):
        """
        Create a string with all the current routes found by traceroute packets and
        whether they are correct.
        """
        self.routes_lock.acquire()
        route_strings = []
        all_correcct = True
        for src, dst in self.routes:
            route, is_good, _ = self.routes[(src, dst)]
            info = "" if (is_good or not label_incorrect) else "Incorrect Route"
            route_strings.append(f"{src} -> {dst}: {route} {info}")
            if not is_good:
                all_correcct = False
        route_strings.sort()
        if all_correcct and len(self.routes) > 0:
            route_strings.append("\nSUCCESS: All Routes correct!")
        else:
            route_strings.append("\nFAILURE: Not all routes are correct")
        route_string = "\n".join(route_strings)
        self.routes_lock.release()
        return route_string

    def get_route_pickle(self):
        """Create a pickle with the current routes found by traceroute packets."""
        self.routes_lock.acquire()
        route_pickle = pickle.dumps(self.routes)
        self.routes_lock.release()
        return route_pickle

    def reset_routes(self):
        """Reset the routes found by traceroute packets."""
        self.routes_lock.acquire()
        self.routes = {}
        self.routes_lock.release()

    def final_routes(self):
        """Have the clients send one final batch of traceroute packets."""
        self.reset_routes()
        for client in self.clients.values():
            client.last_send()
        time.sleep(4 * self.client_send_rate / 1000)

    def join_all(self):
        if self.changes:
            self.handle_changes_thread.join()
        for thread in self.threads:
            thread.join()

    def handle_interrupt(self, signum, frame):
        self.join_all()
        print("")
        quit()


def main():
    parser = argparse.ArgumentParser(description="Run a network simulation.")
    parser.add_argument(
        "net_json_path",
        type=str,
        help="Path to the network simulation configuration file (JSON).",
    )
    parser.add_argument(
        "router",
        type=str,
        choices=["DV", "LS"],
        nargs="?",
        default=None,
        help="DV for DVrouter and LS for LSrouter. If not provided, Router is used.",
    )
    args = parser.parse_args()

    RouterClass = Router
    if args.router == "DV":
        from DVrouter import DVrouter

        RouterClass = DVrouter
    elif args.router == "LS":
        from LSrouter import LSrouter

        RouterClass = LSrouter

    net = Network(args.net_json_path, RouterClass, visualize=False)
    net.run()


class RouterThread(threading.Thread):
    def __init__(self, router):
        threading.Thread.__init__(self)
        self.router = router

    def run(self):
        self.router.run()

    def join(self, timeout=None):
        # Terrible style (think about changing) but works like a charm
        self.router.keep_running = False
        super(RouterThread, self).join(timeout)


class ClientThread(threading.Thread):

    def __init__(self, client):
        threading.Thread.__init__(self)
        self.client = client

    def run(self):
        self.client.run()

    def join(self, timeout=None):
        # Terrible style (think about changing) but works like a charm
        self.client.keep_running = False
        super(ClientThread, self).join(timeout)


class HandleChangesThread(threading.Thread):

    def __init__(self, network):
        threading.Thread.__init__(self)
        self.network = network

    def run(self):
        self.network.handle_changes()


if __name__ == "__main__":
    main()
